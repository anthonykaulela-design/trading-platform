/**
 * ============================================================================
 * L3 MARKETS - Exness API Backend Engine (Document1.pdf Specification)
 * Ed25519 Signing • Access Point Discovery • Account & Positions • Live WS Ticks
 * Credentials & Base URLs loaded strictly from .env
 * ============================================================================
 */

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const http = require('http');
const crypto = require('crypto');
const WebSocket = require('ws');
require('dotenv').config();

const PORT = process.env.PORT || 10000;
const EXNESS_API_KEY = (process.env.EXNESS_API_KEY || '').trim();
const EXNESS_PRIVATE_KEY_RAW = (
    process.env.EXNESS_PRIVATE_KEY ||
    process.env.EXNESS_SECRET_KEY ||
    ''
).trim();
const DEFAULT_ACCOUNT_ID = (process.env.EXNESS_ACCOUNT_ID || '').trim();

const BASE_URL = (process.env.EXNESS_BASE_URL || 'https://api.exness.com').replace(/\/+$/, '');
const DISCOVERY_BASE_URL = (process.env.EXNESS_DISCOVERY_BASE_URL || BASE_URL).replace(/\/+$/, '');
const ALT_BASE_URL = (process.env.EXNESS_ALT_BASE_URL || '').replace(/\/+$/, '');

const EMPTY_BODY_HASH = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU';

const accessPointCache = new Map();
const latestTicks = new Map();
const candleSeries = new Map();
const recentEvents = [];

let upstreamTicksWs = null;
let upstreamEventsWs = null;
let subscribedTickSymbol = 'EURUSD';

const app = express();
const server = http.createServer(app);

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

function toBase64Url(bufOrStr) {
    const buf = Buffer.isBuffer(bufOrStr) ? bufOrStr : Buffer.from(bufOrStr, 'utf8');
    return buf
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

function loadEd25519PrivateKey(rawKey) {
    if (!rawKey) {
        throw new Error('EXNESS_PRIVATE_KEY is not configured in .env.');
    }

    if (rawKey.includes('BEGIN PRIVATE KEY')) {
        return crypto.createPrivateKey({
            key: rawKey,
            format: 'pem',
            type: 'pkcs8'
        });
    }

    const cleanedHex = rawKey.replace(/^0x/i, '').replace(/\s+/g, '');
    if (/^[0-9a-fA-F]{128}$/.test(cleanedHex)) {
        const seed32 = Buffer.from(cleanedHex.slice(0, 64), 'hex');
        const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
        const derKey = Buffer.concat([pkcs8Prefix, seed32]);
        return crypto.createPrivateKey({
            key: derKey,
            format: 'der',
            type: 'pkcs8'
        });
    }

    if (/^[0-9a-fA-F]{64}$/.test(cleanedHex)) {
        const seed32 = Buffer.from(cleanedHex, 'hex');
        const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
        const derKey = Buffer.concat([pkcs8Prefix, seed32]);
        return crypto.createPrivateKey({
            key: derKey,
            format: 'der',
            type: 'pkcs8'
        });
    }

    throw new Error('Unsupported EXNESS_PRIVATE_KEY format. Expected 128-hex (or 64-hex seed) or PKCS#8 PEM.');
}

function createSignedExnessHeaders(apiKey, rawPrivateKey, method = 'GET', pathAndQuery = '', rawBodyStr = '') {
    const privateKeyObj = loadEd25519PrivateKey(rawPrivateKey);
    const upperMethod = String(method || 'GET').toUpperCase();
    const isGet = upperMethod === 'GET';
    const timestampMs = Date.now();
    const idempotencyKey = isGet
        ? ''
        : `l3_${timestampMs}_${crypto.randomBytes(6).toString('hex')}`;

    const bodyHash = isGet || !rawBodyStr
        ? EMPTY_BODY_HASH
        : toBase64Url(crypto.createHash('sha256').update(rawBodyStr, 'utf8').digest());

    const payloadObj = {
        api_key: apiKey,
        idempotency_key: idempotencyKey,
        timestamp: timestampMs,
        sign_version: 1,
        method: upperMethod,
        path: pathAndQuery,
        body_hash: bodyHash
    };

    const decodedBytes = Buffer.from(JSON.stringify(payloadObj), 'utf8');
    const exnData = toBase64Url(decodedBytes);
    const signatureBytes = crypto.sign(null, decodedBytes, privateKeyObj);
    const exnSign = toBase64Url(signatureBytes);

    return {
        'EXN-API-KEY': apiKey,
        'EXN-IDEMPOTENCY-KEY': idempotencyKey,
        'EXN-TIMESTAMP': String(timestampMs),
        'EXN-SIGN-VERSION': '1',
        'EXN-DATA': exnData,
        'EXN-SIGN': exnSign
    };
}

async function resolveAccessPoint(accountId, forceRefresh = false) {
    const acct = String(accountId || '').trim();
    if (!acct) {
        throw new Error('account_id is required to resolve Exness Access Point.');
    }

    if (!forceRefresh && accessPointCache.has(acct)) {
        return accessPointCache.get(acct);
    }

    const pathAndQuery = `/v1/trading/access-point?account_id=${encodeURIComponent(acct)}`;
    const hosts = [...new Set([DISCOVERY_BASE_URL, BASE_URL, ALT_BASE_URL].filter(Boolean))];

    let lastError = null;
    for (const host of hosts) {
        try {
            const headers = createSignedExnessHeaders(EXNESS_API_KEY, EXNESS_PRIVATE_KEY_RAW, 'GET', pathAndQuery, '');
            const res = await axios.get(`${host}${pathAndQuery}`, {
                headers: { ...headers, Accept: 'application/json' },
                maxRedirects: 0,
                timeout: 10000
            });

            const accessPoint = String(
                res.data?.access_point || res.data?.data?.access_point || ''
            ).replace(/\/+$/, '');

            if (accessPoint) {
                const entry = {
                    accountId: String(res.data?.account_id ?? acct),
                    accessPoint,
                    discoveryHost: host,
                    resolvedAt: Date.now()
                };
                accessPointCache.set(acct, entry);
                return entry;
            }
        } catch (err) {
            lastError = err;
        }
    }

    throw lastError || new Error('Failed to resolve Exness account Access Point.');
}

async function signedRestRequest(host, method, pathAndQuery, bodyObj = null) {
    const upperMethod = method.toUpperCase();
    const rawBody = bodyObj !== null && bodyObj !== undefined ? JSON.stringify(bodyObj) : '';
    const headers = createSignedExnessHeaders(
        EXNESS_API_KEY,
        EXNESS_PRIVATE_KEY_RAW,
        upperMethod,
        pathAndQuery,
        rawBody
    );

    return axios({
        method: upperMethod,
        url: `${String(host).replace(/\/+$/, '')}${pathAndQuery}`,
        data: upperMethod === 'GET' ? undefined : rawBody,
        headers: {
            ...headers,
            Accept: 'application/json',
            ...(upperMethod !== 'GET' ? { 'Content-Type': 'application/json' } : {})
        },
        maxRedirects: 0,
        timeout: 10000
    });
}

function timeframeToMs(tf) {
    const map = {
        '1m': 60 * 1000,
        '5m': 5 * 60 * 1000,
        '15m': 15 * 60 * 1000,
        '1h': 60 * 60 * 1000
    };
    return map[tf] || 60 * 1000;
}

function recordTickIntoCandles(symbol, bid, ask, tsMs = Date.now()) {
    const sym = String(symbol || '').toUpperCase();
    const mid = Number.isFinite(bid) && Number.isFinite(ask)
        ? (bid + ask) / 2
        : (Number.isFinite(bid) ? bid : ask);

    if (!sym || !Number.isFinite(mid)) return;

    latestTicks.set(sym, {
        symbol: sym,
        bid: Number.isFinite(bid) ? bid : mid,
        ask: Number.isFinite(ask) ? ask : mid,
        mid,
        timestamp: tsMs
    });

    for (const tf of ['1m', '5m', '15m', '1h']) {
        const key = `${sym}:${tf}`;
        const bucketMs = timeframeToMs(tf);
        const bucketStart = Math.floor(tsMs / bucketMs) * bucketMs;
        const list = candleSeries.get(key) || [];
        const last = list[list.length - 1];

        if (!last || last.x < bucketStart) {
            list.push({ x: bucketStart, o: mid, h: mid, l: mid, c: mid });
            if (list.length > 300) list.shift();
        } else {
            last.h = Math.max(last.h, mid);
            last.l = Math.min(last.l, mid);
            last.c = mid;
        }
        candleSeries.set(key, list);
    }
}

function connectExnessStreams(accountId, symbol = 'EURUSD') {
    const acct = String(accountId || DEFAULT_ACCOUNT_ID || '').trim();
    if (!acct || !EXNESS_API_KEY || !EXNESS_PRIVATE_KEY_RAW) return;

    subscribedTickSymbol = String(symbol || 'EURUSD').toUpperCase();

    resolveAccessPoint(acct)
        .then(({ accessPoint }) => {
            const wsOrigin = accessPoint.replace(/^http(s?):\/\//i, (_, s) => (s ? 'wss://' : 'ws://'));

            const ticksPath = `/v1/server-events/accounts/${encodeURIComponent(acct)}/ws/ticks`;
            if (!upstreamTicksWs || upstreamTicksWs.readyState === WebSocket.CLOSED) {
                const tickHeaders = createSignedExnessHeaders(EXNESS_API_KEY, EXNESS_PRIVATE_KEY_RAW, 'GET', ticksPath, '');
                upstreamTicksWs = new WebSocket(`${wsOrigin}${ticksPath}`, { headers: tickHeaders });

                upstreamTicksWs.on('open', () => {
                    upstreamTicksWs.send(JSON.stringify({
                        id: `ticks-${subscribedTickSymbol.toLowerCase()}-1`,
                        subscribe: {
                            event: 'ticks',
                            instruments: [subscribedTickSymbol]
                        }
                    }));
                });

                upstreamTicksWs.on('message', (raw) => {
                    try {
                        const msg = JSON.parse(raw.toString());
                        const payload = msg.data || msg.tick || msg;
                        const sym = String(payload.instrument || payload.symbol || subscribedTickSymbol).toUpperCase();
                        const bid = Number(payload.bid ?? payload.b ?? payload.price);
                        const ask = Number(payload.ask ?? payload.a ?? bid);
                        const ts = Number(payload.timestamp || payload.t || Date.now());
                        recordTickIntoCandles(sym, bid, ask, ts < 1e12 ? ts * 1000 : ts);
                        broadcastToClients({ type: 'TICK', symbol: sym, bid, ask, timestamp: ts });
                    } catch (_) {}
                });

                upstreamTicksWs.on('close', () => {
                    upstreamTicksWs = null;
                });
            } else if (upstreamTicksWs.readyState === WebSocket.OPEN) {
                upstreamTicksWs.send(JSON.stringify({
                    id: `ticks-${subscribedTickSymbol.toLowerCase()}-sub`,
                    subscribe: {
                        event: 'ticks',
                        instruments: [subscribedTickSymbol]
                    }
                }));
            }

            const eventsPath = `/v1/server-events/accounts/${encodeURIComponent(acct)}/ws/events`;
            if (!upstreamEventsWs || upstreamEventsWs.readyState === WebSocket.CLOSED) {
                const evtHeaders = createSignedExnessHeaders(EXNESS_API_KEY, EXNESS_PRIVATE_KEY_RAW, 'GET', eventsPath, '');
                upstreamEventsWs = new WebSocket(`${wsOrigin}${eventsPath}`, { headers: evtHeaders });

                upstreamEventsWs.on('open', () => {
                    upstreamEventsWs.send(JSON.stringify({
                        id: 'subscribe-transactions-1',
                        subscribe: { event: 'transactions' }
                    }));
                    upstreamEventsWs.send(JSON.stringify({
                        id: 'subscribe-account-1',
                        subscribe: { event: 'account' }
                    }));
                });

                upstreamEventsWs.on('message', (raw) => {
                    try {
                        const evt = JSON.parse(raw.toString());
                        recentEvents.unshift({ receivedAt: new Date().toISOString(), event: evt });
                        if (recentEvents.length > 100) recentEvents.pop();
                        broadcastToClients({ type: 'EXNESS_EVENT', event: evt });
                    } catch (_) {}
                });

                upstreamEventsWs.on('close', () => {
                    upstreamEventsWs = null;
                });
            }
        })
        .catch((err) => {
            console.warn('[L3 Markets Stream Connect]:', err.response?.data || err.message);
        });
}

async function fetchExnessAccountSummary(accountId, fallbackLabel = 'Exness Account') {
    const acct = String(accountId || '').trim();
    const baseRecord = {
        login: acct || fallbackLabel,
        accountType: 'Exness Trader API',
        currency: 'USD',
        balance: 0,
        equity: 0,
        leverage: '',
        status: acct ? 'Pending Discovery' : 'Set EXNESS_ACCOUNT_ID in .env'
    };

    if (!acct || !EXNESS_API_KEY || !EXNESS_PRIVATE_KEY_RAW) {
        return { account: baseRecord, accessPoint: null, rawConfig: null };
    }

    try {
        const discovery = await resolveAccessPoint(acct);
        const configPath = `/v1/configuration/accounts/${encodeURIComponent(acct)}/account`;
        const res = await signedRestRequest(discovery.accessPoint, 'GET', configPath);
        const cfg = res.data?.data || res.data || {};

        return {
            account: {
                login: String(cfg.account_id ?? acct),
                accountType: cfg.account_type || cfg.type || 'Exness Trader API',
                currency: cfg.currency || 'USD',
                balance: Number(cfg.balance ?? 0),
                equity: Number(cfg.equity ?? cfg.balance ?? 0),
                leverage: cfg.leverage ? String(cfg.leverage) : '',
                marginCallLevel: cfg.margin_call_level ?? null,
                stopOutLevel: cfg.stop_out_level ?? null,
                status: 'Connected'
            },
            accessPoint: discovery.accessPoint,
            rawConfig: cfg
        };
    } catch (err) {
        console.warn('[L3 Markets Account Fetch]:', err.response?.status, err.response?.data || err.message);
        return {
            account: {
                ...baseRecord,
                status: `Error (${err.response?.status || err.code || 'Gateway'})`
            },
            accessPoint: accessPointCache.get(acct)?.accessPoint || null,
            rawConfig: null
        };
    }
}

const wss = new WebSocket.Server({ server });
function broadcastToClients(payloadObj) {
    const raw = JSON.stringify(payloadObj);
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(raw);
        }
    });
}

wss.on('connection', (ws) => {
    ws.send(JSON.stringify({
        type: 'SYSTEM_STATUS',
        platform: 'L3 Markets',
        status: 'CONNECTED',
        discoveryBaseUrl: DISCOVERY_BASE_URL,
        notice: 'All trades, positions, account balances, and market data are handled, processed, and kept directly by Exness.'
    }));
});

app.get('/health', async (req, res) => {
    const accountId = String(req.query.account_id || DEFAULT_ACCOUNT_ID || '').trim();
    let accessPoint = accessPointCache.get(accountId)?.accessPoint || null;

    if (!accessPoint && accountId && EXNESS_API_KEY && EXNESS_PRIVATE_KEY_RAW) {
        try {
            const disc = await resolveAccessPoint(accountId);
            accessPoint = disc.accessPoint;
        } catch (_) {}
    }

    res.status(200).json({
        status: 'ONLINE',
        platform: 'L3 Markets',
        broker: 'Exness',
        discoveryBaseUrl: DISCOVERY_BASE_URL,
        accessPoint,
        accountConfigured: Boolean(accountId),
        credentialsLoadedFromEnv: Boolean(EXNESS_API_KEY && EXNESS_PRIVATE_KEY_RAW),
        notice: 'All trades, positions, account balances, and market data are handled, processed, and kept directly by Exness.',
        timestamp: new Date().toISOString()
    });
});

app.get('/api/exness/access-point', async (req, res) => {
    const accountId = String(req.query.account_id || DEFAULT_ACCOUNT_ID || '').trim();
    if (!accountId) {
        return res.status(400).json({ success: false, message: 'account_id query parameter is required.' });
    }

    try {
        const discovery = await resolveAccessPoint(accountId, Boolean(req.query.refresh));
        res.json({
            success: true,
            account_id: discovery.accountId,
            access_point: discovery.accessPoint,
            discovery_host: discovery.discoveryHost
        });
    } catch (error) {
        res.status(error.response?.status || 500).json({
            success: false,
            error: error.response?.data || { message: error.message }
        });
    }
});

app.post('/api/exness/login', async (req, res) => {
    const email = String(req.body.email || '').trim();
    const password = String(req.body.password || '');
    const accountId = String(req.body.accountId || req.body.account_id || DEFAULT_ACCOUNT_ID || '').trim();

    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: 'Email address and password are required.'
        });
    }

    const sessionToken = `l3_session_${crypto.randomBytes(16).toString('hex')}`;
    const summary = await fetchExnessAccountSummary(accountId, email);
    connectExnessStreams(accountId, subscribedTickSymbol);

    res.json({
        success: true,
        platform: 'L3 Markets',
        token: sessionToken,
        user: email,
        account_id: accountId || null,
        discovery_base_url: DISCOVERY_BASE_URL,
        access_point: summary.accessPoint,
        notice: 'All trades, positions, account balances, and market data are handled, processed, and kept directly by Exness.',
        accounts: [summary.account],
        recentEvents
    });
});

app.post('/api/exness/refresh-session', async (req, res) => {
    const token = String(req.body.token || '').trim();
    const email = String(req.body.email || '').trim();
    const accountId = String(req.body.accountId || req.body.account_id || DEFAULT_ACCOUNT_ID || '').trim();

    if (!token) {
        return res.status(401).json({ success: false, message: 'Session token required.' });
    }

    const summary = await fetchExnessAccountSummary(accountId, email || 'Exness Account');
    connectExnessStreams(accountId, subscribedTickSymbol);

    res.json({
        success: true,
        user: email || null,
        account_id: accountId || null,
        discovery_base_url: DISCOVERY_BASE_URL,
        access_point: summary.accessPoint,
        accounts: [summary.account],
        recentEvents
    });
});

app.get('/api/exness/candles', async (req, res) => {
    const symbol = String(req.query.symbol || 'EURUSD').trim().toUpperCase();
    const timeframe = String(req.query.timeframe || '1m').trim();
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 300);
    const accountId = String(req.query.account_id || DEFAULT_ACCOUNT_ID || '').trim();

    connectExnessStreams(accountId, symbol);

    const series = candleSeries.get(`${symbol}:${timeframe}`) || [];
    const candles = series.slice(-limit);

    res.json({
        success: true,
        symbol,
        timeframe,
        source: 'exness_ws_ticks',
        latestTick: latestTicks.get(symbol) || null,
        candles
    });
});

app.post('/api/exness/instruments', async (req, res) => {
    const accountId = String(req.body.accountId || req.body.account_id || DEFAULT_ACCOUNT_ID || '').trim();

    if (accountId && EXNESS_API_KEY && EXNESS_PRIVATE_KEY_RAW) {
        try {
            const discovery = await resolveAccessPoint(accountId);
            const pathAndQuery = `/v1/trading/accounts/${encodeURIComponent(accountId)}/instruments`;
            const response = await signedRestRequest(discovery.accessPoint, 'GET', pathAndQuery);
            const list = Array.isArray(response.data)
                ? response.data
                : response.data?.instruments || response.data?.items || response.data?.data || [];

            if (Array.isArray(list) && list.length > 0) {
                return res.json({
                    success: true,
                    source: 'exness',
                    instruments: { exness_instruments: list }
                });
            }
        } catch (err) {
            console.warn('[L3 Markets Instruments]:', err.response?.status, err.response?.data || err.message);
        }
    }

    return res.json({
        success: true,
        source: 'none',
        instruments: {}
    });
});

app.post('/api/exness/trade', async (req, res) => {
    const accountId = String(req.body.accountId || req.body.account_id || DEFAULT_ACCOUNT_ID || '').trim();
    const instrument = String(req.body.symbol || req.body.instrument || '').trim().toUpperCase();
    const volume = String(req.body.volume ?? '').trim();
    const side = String(req.body.side || req.body.orderType || '').trim().toLowerCase();

    if (!accountId) {
        return res.status(400).json({
            success: false,
            message: 'EXNESS_ACCOUNT_ID must be configured in .env for Trader API position requests.'
        });
    }

    if (!instrument || !volume || Number(volume) <= 0 || !['buy', 'sell'].includes(side)) {
        return res.status(400).json({
            success: false,
            message: 'Valid instrument/symbol, positive volume, and side (buy or sell) are required.'
        });
    }

    try {
        const discovery = await resolveAccessPoint(accountId);
        const positionPath = `/v1/trading/accounts/${encodeURIComponent(accountId)}/positions`;
        const orderBody = {
            instrument,
            side,
            volume
        };

        const orderRes = await signedRestRequest(discovery.accessPoint, 'POST', positionPath, orderBody);
        const ack = orderRes.data || {};
        const summary = await fetchExnessAccountSummary(accountId);

        res.json({
            success: true,
            message: 'Position request accepted by Exness (asynchronous ACK).',
            operation_id: ack.operation_id || null,
            client_request_id: ack.client_request_id || null,
            status: ack.status || 'accepted',
            order: ack,
            accounts: [summary.account],
            recentEvents
        });
    } catch (error) {
        const statusCode = error.response?.status || 500;
        res.status(statusCode).json({
            success: false,
            message: error.response?.data?.message || error.message || 'Trade request failed via Exness.'
        });
    }
});

server.listen(PORT, '0.0.0.0', () => {
    console.log('============================================================');
    console.log(` L3 Markets Engine listening on port ${PORT}`);
    console.log(` Discovery Gateway Base URL: ${DISCOVERY_BASE_URL}`);
    console.log('============================================================');
});