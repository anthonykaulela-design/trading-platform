/**
 * ============================================================================
 * L3 MARKETS - Exness API Backend Engine
 * Ed25519 Signing • Key Management Gateway • Account & Positions • Live WS Ticks
 * Credentials & Gateway URL loaded strictly from .env
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

const GATEWAY_URL = (
    process.env.EXNESS_GATEWAY_URL ||
    process.env.EXNESS_DISCOVERY_BASE_URL ||
    process.env.EXNESS_BASE_URL ||
    ''
).trim().replace(/\/+$/, '');
const ALT_GATEWAY_URL = (process.env.EXNESS_ALT_GATEWAY_URL || process.env.EXNESS_ALT_BASE_URL || '')
    .trim()
    .replace(/\/+$/, '');

const EMPTY_BODY_HASH = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU';
const VALID_TIMEFRAMES = new Set(['1m', '5m', '15m', '1h']);
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

const accessPointCache = new Map();
const latestTicks = new Map();
const candleSeries = new Map();
const activeSessions = new Map();
const recentEvents = [];

let upstreamTicksWs = null;
let upstreamEventsWs = null;
let subscribedTickSymbol = 'EURUSD';
let activeStreamAccountId = '';
let ticksReconnectTimer = null;
let eventsReconnectTimer = null;
let ticksReconnectAttempts = 0;
let eventsReconnectAttempts = 0;

const app = express();
const server = http.createServer(app);

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

function hasValidGatewayUrl() {
    if (!GATEWAY_URL) return false;
    try {
        const parsed = new URL(GATEWAY_URL);
        return parsed.protocol === 'https:' || parsed.protocol === 'http:';
    } catch (_) {
        return false;
    }
}

function getGatewayHosts() {
    const hosts = [GATEWAY_URL, ALT_GATEWAY_URL].filter(Boolean);
    return [...new Set(hosts)];
}

function issueSessionToken(accountId, label) {
    const token = `l3_session_${crypto.randomBytes(24).toString('hex')}`;
    const now = Date.now();
    activeSessions.set(token, {
        token,
        accountId,
        label: label || accountId,
        createdAt: now,
        expiresAt: now + SESSION_TTL_MS
    });
    return token;
}

function validateSessionToken(rawToken) {
    const token = String(rawToken || '').trim();
    if (!token) return null;
    const session = activeSessions.get(token);
    if (!session) return null;
    if (Date.now() > session.expiresAt) {
        activeSessions.delete(token);
        return null;
    }
    session.expiresAt = Date.now() + SESSION_TTL_MS;
    return session;
}

function extractTokenFromReq(req) {
    const authHeader = String(req.headers.authorization || '').trim();
    if (authHeader.toLowerCase().startsWith('bearer ')) {
        return authHeader.slice(7).trim();
    }
    return String(req.body?.token || req.query?.token || '').trim();
}

function requireValidSession(req, res, next) {
    const token = extractTokenFromReq(req);
    const session = validateSessionToken(token);
    if (!session) {
        return res.status(401).json({
            success: false,
            message: 'Invalid or expired session token. Please sign in again.'
        });
    }
    req.session = session;
    return next();
}

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
    if (!apiKey) {
        throw new Error('EXNESS_API_KEY is not configured in .env.');
    }
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
    if (!/^\d+$/.test(acct)) {
        throw new Error('A valid numeric account_id is required to resolve Exness Access Point.');
    }
    if (!hasValidGatewayUrl()) {
        throw new Error('EXNESS_GATEWAY_URL is not configured in .env. Set the Gateway URL from Exness Key Management.');
    }

    if (!forceRefresh && accessPointCache.has(acct)) {
        return accessPointCache.get(acct);
    }

    const pathAndQuery = `/v1/trading/access-point?account_id=${encodeURIComponent(acct)}`;
    const hosts = getGatewayHosts();

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
            lastError = new Error(`Gateway ${host} returned no access_point.`);
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
    return map[tf];
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

    for (const tf of VALID_TIMEFRAMES) {
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

function scheduleTicksReconnect() {
    if (ticksReconnectTimer) return;
    if (!/^\d+$/.test(activeStreamAccountId)) return;
    const delayMs = Math.min(1000 * (2 ** ticksReconnectAttempts), 30000);
    ticksReconnectAttempts += 1;
    ticksReconnectTimer = setTimeout(() => {
        ticksReconnectTimer = null;
        openTicksSocket(activeStreamAccountId, subscribedTickSymbol);
    }, delayMs);
}

function scheduleEventsReconnect() {
    if (eventsReconnectTimer) return;
    if (!/^\d+$/.test(activeStreamAccountId)) return;
    const delayMs = Math.min(1000 * (2 ** eventsReconnectAttempts), 30000);
    eventsReconnectAttempts += 1;
    eventsReconnectTimer = setTimeout(() => {
        eventsReconnectTimer = null;
        openEventsSocket(activeStreamAccountId);
    }, delayMs);
}

function openTicksSocket(acct, symbol) {
    if (upstreamTicksWs && (upstreamTicksWs.readyState === WebSocket.OPEN || upstreamTicksWs.readyState === WebSocket.CONNECTING)) {
        if (upstreamTicksWs.readyState === WebSocket.OPEN) {
            upstreamTicksWs.send(JSON.stringify({
                id: `ticks-${symbol.toLowerCase()}-${Date.now()}`,
                subscribe: {
                    event: 'ticks',
                    instruments: [symbol]
                }
            }));
        }
        return;
    }

    resolveAccessPoint(acct)
        .then(({ accessPoint }) => {
            const wsOrigin = accessPoint.replace(/^http(s?):\/\//i, (_, s) => (s ? 'wss://' : 'ws://'));
            const ticksPath = `/v1/server-events/accounts/${encodeURIComponent(acct)}/ws/ticks`;
            const tickHeaders = createSignedExnessHeaders(EXNESS_API_KEY, EXNESS_PRIVATE_KEY_RAW, 'GET', ticksPath, '');
            const ws = new WebSocket(`${wsOrigin}${ticksPath}`, { headers: tickHeaders });
            upstreamTicksWs = ws;

            ws.on('open', () => {
                ticksReconnectAttempts = 0;
                ws.send(JSON.stringify({
                    id: `ticks-${symbol.toLowerCase()}-1`,
                    subscribe: {
                        event: 'ticks',
                        instruments: [subscribedTickSymbol]
                    }
                }));
            });

            ws.on('message', (raw) => {
                try {
                    const msg = JSON.parse(raw.toString());
                    const payload = msg.data || msg.tick || msg;
                    const sym = String(payload.instrument || payload.symbol || subscribedTickSymbol).toUpperCase();
                    const bid = Number(payload.bid ?? payload.b ?? payload.price);
                    const ask = Number(payload.ask ?? payload.a ?? bid);
                    const ts = Number(payload.timestamp || payload.t || Date.now());
                    recordTickIntoCandles(sym, bid, ask, ts < 1e12 ? ts * 1000 : ts);
                    broadcastToClients({ type: 'TICK', symbol: sym, bid, ask, timestamp: ts });
                } catch (err) {
                    console.warn('[L3 Markets Ticks Parse]:', err.message);
                }
            });

            ws.on('error', (err) => {
                console.warn('[L3 Markets Ticks WS Error]:', err.message);
            });

            ws.on('close', () => {
                if (upstreamTicksWs === ws) {
                    upstreamTicksWs = null;
                }
                scheduleTicksReconnect();
            });
        })
        .catch((err) => {
            console.warn('[L3 Markets Ticks Connect]:', err.response?.data || err.message);
            scheduleTicksReconnect();
        });
}

function openEventsSocket(acct) {
    if (upstreamEventsWs && (upstreamEventsWs.readyState === WebSocket.OPEN || upstreamEventsWs.readyState === WebSocket.CONNECTING)) {
        return;
    }

    resolveAccessPoint(acct)
        .then(({ accessPoint }) => {
            const wsOrigin = accessPoint.replace(/^http(s?):\/\//i, (_, s) => (s ? 'wss://' : 'ws://'));
            const eventsPath = `/v1/server-events/accounts/${encodeURIComponent(acct)}/ws/events`;
            const evtHeaders = createSignedExnessHeaders(EXNESS_API_KEY, EXNESS_PRIVATE_KEY_RAW, 'GET', eventsPath, '');
            const ws = new WebSocket(`${wsOrigin}${eventsPath}`, { headers: evtHeaders });
            upstreamEventsWs = ws;

            ws.on('open', () => {
                eventsReconnectAttempts = 0;
                ws.send(JSON.stringify({
                    id: 'subscribe-transactions-1',
                    subscribe: { event: 'transactions' }
                }));
                ws.send(JSON.stringify({
                    id: 'subscribe-accounts-1',
                    subscribe: { event: 'accounts' }
                }));
            });

            ws.on('message', (raw) => {
                try {
                    const evt = JSON.parse(raw.toString());
                    recentEvents.unshift({ receivedAt: new Date().toISOString(), event: evt });
                    if (recentEvents.length > 100) recentEvents.pop();
                    broadcastToClients({ type: 'EXNESS_EVENT', event: evt });
                } catch (err) {
                    console.warn('[L3 Markets Event Parse]:', err.message);
                }
            });

            ws.on('error', (err) => {
                console.warn('[L3 Markets Events WS Error]:', err.message);
            });

            ws.on('close', () => {
                if (upstreamEventsWs === ws) {
                    upstreamEventsWs = null;
                }
                scheduleEventsReconnect();
            });
        })
        .catch((err) => {
            console.warn('[L3 Markets Events Connect]:', err.response?.data || err.message);
            scheduleEventsReconnect();
        });
}

function connectExnessStreams(accountId, symbol = 'EURUSD') {
    const acct = String(accountId || '').trim();
    if (!/^\d+$/.test(acct) || !EXNESS_API_KEY || !EXNESS_PRIVATE_KEY_RAW || !hasValidGatewayUrl()) {
        return;
    }

    if (activeStreamAccountId && activeStreamAccountId !== acct) {
        if (upstreamTicksWs) {
            upstreamTicksWs.terminate();
            upstreamTicksWs = null;
        }
        if (upstreamEventsWs) {
            upstreamEventsWs.terminate();
            upstreamEventsWs = null;
        }
        if (ticksReconnectTimer) {
            clearTimeout(ticksReconnectTimer);
            ticksReconnectTimer = null;
        }
        if (eventsReconnectTimer) {
            clearTimeout(eventsReconnectTimer);
            eventsReconnectTimer = null;
        }
    }

    activeStreamAccountId = acct;
    subscribedTickSymbol = String(symbol || 'EURUSD').toUpperCase();

    openTicksSocket(acct, subscribedTickSymbol);
    openEventsSocket(acct);
}

async function fetchExnessAccountSummary(accountId, fallbackLabel = '') {
    const acct = String(accountId || '').trim();
    const baseRecord = {
        login: acct,
        label: fallbackLabel || acct,
        accountType: 'Exness Trader API',
        currency: 'USD',
        balance: 0,
        equity: 0,
        leverage: '',
        connected: false,
        status: 'Disconnected'
    };

    if (!/^\d+$/.test(acct)) {
        return {
            connected: false,
            account: { ...baseRecord, status: 'Invalid Account ID' },
            accessPoint: null,
            rawConfig: null,
            errorMessage: 'A valid numeric Exness Account ID is required.'
        };
    }

    if (!hasValidGatewayUrl()) {
        return {
            connected: false,
            account: { ...baseRecord, status: 'Missing Gateway URL' },
            accessPoint: null,
            rawConfig: null,
            errorMessage: 'EXNESS_GATEWAY_URL must be set to the Gateway URL from Exness Key Management.'
        };
    }

    if (!EXNESS_API_KEY || !EXNESS_PRIVATE_KEY_RAW) {
        return {
            connected: false,
            account: { ...baseRecord, status: 'Missing API Credentials' },
            accessPoint: null,
            rawConfig: null,
            errorMessage: 'EXNESS_API_KEY and EXNESS_PRIVATE_KEY must be configured in .env.'
        };
    }

    try {
        const discovery = await resolveAccessPoint(acct);
        const configPath = `/v1/configuration/accounts/${encodeURIComponent(acct)}/account`;
        const res = await signedRestRequest(discovery.accessPoint, 'GET', configPath);
        const cfg = res.data?.data || res.data || {};

        return {
            connected: true,
            account: {
                login: String(cfg.account_id ?? acct),
                label: fallbackLabel || String(cfg.account_id ?? acct),
                accountType: cfg.account_type || cfg.type || 'Exness Trader API',
                currency: cfg.currency || 'USD',
                balance: Number(cfg.balance ?? 0),
                equity: Number(cfg.equity ?? cfg.balance ?? 0),
                leverage: cfg.leverage ? String(cfg.leverage) : '',
                marginCallLevel: cfg.margin_call_level ?? null,
                stopOutLevel: cfg.stop_out_level ?? null,
                connected: true,
                status: 'Connected'
            },
            accessPoint: discovery.accessPoint,
            rawConfig: cfg,
            errorMessage: null
        };
    } catch (err) {
        const upstreamStatus = err.response?.status;
        const detail = err.response?.data?.message || err.message || 'Connection failed';
        console.warn('[L3 Markets Account Fetch]:', upstreamStatus || err.code || 'ERR', detail);
        return {
            connected: false,
            account: {
                ...baseRecord,
                connected: false,
                status: upstreamStatus ? `Failed (HTTP ${upstreamStatus})` : 'Connection Failed',
                error: detail
            },
            accessPoint: accessPointCache.get(acct)?.accessPoint || null,
            rawConfig: null,
            errorMessage: detail
        };
    }
}

const wss = new WebSocket.Server({ server });
function broadcastToClients(payloadObj) {
    const raw = JSON.stringify(payloadObj);
    wss.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(raw, (err) => {
                if (err) console.warn('[L3 Markets Client WS Send]:', err.message);
            });
        }
    });
}

wss.on('connection', (ws) => {
    ws.on('error', (err) => {
        console.warn('[L3 Markets Client WS Error]:', err.message);
    });
    ws.send(JSON.stringify({
        type: 'SYSTEM_STATUS',
        platform: 'L3 Markets',
        status: 'CONNECTED',
        gatewayConfigured: hasValidGatewayUrl(),
        notice: 'All trades, positions, account balances, and market data are handled, processed, and kept directly by Exness.'
    }));
});

app.get('/health', async (req, res) => {
    const accountId = String(req.query.account_id || DEFAULT_ACCOUNT_ID || '').trim();
    const gatewayReady = hasValidGatewayUrl();
    const credentialsReady = Boolean(EXNESS_API_KEY && EXNESS_PRIVATE_KEY_RAW);
    let accessPoint = accessPointCache.get(accountId)?.accessPoint || null;

    if (!accessPoint && /^\d+$/.test(accountId) && gatewayReady && credentialsReady) {
        try {
            const disc = await resolveAccessPoint(accountId);
            accessPoint = disc.accessPoint;
        } catch (_) {}
    }

    res.status(200).json({
        status: 'ONLINE',
        platform: 'L3 Markets',
        broker: 'Exness',
        gatewayConfigured: gatewayReady,
        accessPoint,
        accountConfigured: /^\d+$/.test(accountId),
        credentialsLoadedFromEnv: credentialsReady,
        notice: 'All trades, positions, account balances, and market data are handled, processed, and kept directly by Exness.',
        timestamp: new Date().toISOString()
    });
});

app.get('/api/exness/access-point', requireValidSession, async (req, res) => {
    const accountId = String(req.query.account_id || req.session.accountId || '').trim();
    if (!/^\d+$/.test(accountId)) {
        return res.status(400).json({
            success: false,
            message: 'A valid numeric account_id query parameter is required.'
        });
    }

    try {
        const discovery = await resolveAccessPoint(accountId, Boolean(req.query.refresh));
        return res.json({
            success: true,
            account_id: discovery.accountId,
            access_point: discovery.accessPoint,
            discovery_host: discovery.discoveryHost
        });
    } catch (error) {
        return res.status(error.response?.status || 500).json({
            success: false,
            message: error.response?.data?.message || error.message,
            error: error.response?.data || { message: error.message }
        });
    }
});

app.post('/api/exness/login', async (req, res) => {
    const accountId = String(req.body.accountId || req.body.account_id || '').trim();
    const label = String(req.body.label || req.body.email || '').trim();

    if (!/^\d+$/.test(accountId)) {
        return res.status(400).json({
            success: false,
            message: 'A valid Exness Account ID (numeric string) is required to sign in.'
        });
    }

    try {
        const summary = await fetchExnessAccountSummary(accountId, label || accountId);
        if (!summary.connected) {
            return res.status(502).json({
                success: false,
                connected: false,
                message: summary.errorMessage || 'Failed to connect to Exness account.',
                account_id: accountId,
                access_point: summary.accessPoint,
                accounts: [summary.account]
            });
        }

        const sessionToken = issueSessionToken(accountId, label || accountId);
        connectExnessStreams(accountId, subscribedTickSymbol);

        return res.json({
            success: true,
            connected: true,
            platform: 'L3 Markets',
            token: sessionToken,
            user: label || accountId,
            account_id: accountId,
            access_point: summary.accessPoint,
            notice: 'All trades, positions, account balances, and market data are handled, processed, and kept directly by Exness.',
            accounts: [summary.account],
            recentEvents
        });
    } catch (error) {
        console.error('[L3 Markets Login Error]:', error.message);
        return res.status(500).json({
            success: false,
            connected: false,
            message: error.message || 'Failed to initialize Exness session.'
        });
    }
});

app.post('/api/exness/refresh-session', requireValidSession, async (req, res) => {
    const accountId = String(req.body.accountId || req.body.account_id || req.session.accountId || '').trim();
    const label = String(req.body.label || req.body.email || req.session.label || '').trim();

    if (!/^\d+$/.test(accountId)) {
        return res.status(400).json({ success: false, message: 'Valid numeric accountId is required.' });
    }

    try {
        const summary = await fetchExnessAccountSummary(accountId, label || accountId);
        if (!summary.connected) {
            return res.status(502).json({
                success: false,
                connected: false,
                message: summary.errorMessage || 'Failed to refresh Exness account connection.',
                user: label || accountId,
                account_id: accountId,
                access_point: summary.accessPoint,
                accounts: [summary.account],
                recentEvents
            });
        }

        connectExnessStreams(accountId, subscribedTickSymbol);

        return res.json({
            success: true,
            connected: true,
            user: label || accountId,
            account_id: accountId,
            access_point: summary.accessPoint,
            accounts: [summary.account],
            recentEvents
        });
    } catch (error) {
        console.error('[L3 Markets Refresh Error]:', error.message);
        return res.status(500).json({
            success: false,
            connected: false,
            message: error.message || 'Failed to refresh Exness session.'
        });
    }
});

app.get('/api/exness/events', requireValidSession, (req, res) => {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
    return res.json({
        success: true,
        account_id: req.session.accountId,
        events: recentEvents.slice(0, limit)
    });
});

app.get('/api/exness/candles', async (req, res) => {
    const symbol = String(req.query.symbol || 'EURUSD').trim().toUpperCase();
    const timeframe = String(req.query.timeframe || '1m').trim();
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 300);
    const accountId = String(req.query.account_id || '').trim();

    if (!VALID_TIMEFRAMES.has(timeframe)) {
        return res.status(400).json({
            success: false,
            message: `Invalid timeframe "${timeframe}". Supported timeframes: ${[...VALID_TIMEFRAMES].join(', ')}.`
        });
    }

    if (/^\d+$/.test(accountId)) {
        connectExnessStreams(accountId, symbol);
    }

    const series = candleSeries.get(`${symbol}:${timeframe}`) || [];
    const candles = series.slice(-limit);

    return res.json({
        success: true,
        symbol,
        timeframe,
        source: 'exness_ws_ticks',
        latestTick: latestTicks.get(symbol) || null,
        candles
    });
});

app.post('/api/exness/instruments', requireValidSession, async (req, res) => {
    const accountId = String(req.body.accountId || req.body.account_id || req.session.accountId || '').trim();

    if (!/^\d+$/.test(accountId)) {
        return res.status(400).json({
            success: false,
            message: 'A valid numeric accountId is required to fetch instruments.'
        });
    }

    if (!EXNESS_API_KEY || !EXNESS_PRIVATE_KEY_RAW || !hasValidGatewayUrl()) {
        return res.status(503).json({
            success: false,
            message: 'Exness Gateway URL or API credentials are not configured on the server.'
        });
    }

    try {
        const discovery = await resolveAccessPoint(accountId);
        const pathAndQuery = `/v1/trading/accounts/${encodeURIComponent(accountId)}/instruments`;
        const response = await signedRestRequest(discovery.accessPoint, 'GET', pathAndQuery);
        const list = Array.isArray(response.data)
            ? response.data
            : response.data?.instruments || response.data?.items || response.data?.data || [];

        if (!Array.isArray(list)) {
            return res.status(502).json({
                success: false,
                message: 'Unexpected instruments payload format from Exness.'
            });
        }

        return res.json({
            success: true,
            source: 'exness',
            instruments: { exness_instruments: list }
        });
    } catch (err) {
        const statusCode = err.response?.status || 502;
        console.warn('[L3 Markets Instruments]:', statusCode, err.response?.data || err.message);
        return res.status(statusCode).json({
            success: false,
            message: err.response?.data?.message || err.message || 'Failed to retrieve instruments from Exness.'
        });
    }
});

app.post('/api/exness/trade', requireValidSession, async (req, res) => {
    const accountId = String(req.body.accountId || req.body.account_id || req.session.accountId || '').trim();
    const instrument = String(req.body.symbol || req.body.instrument || '').trim().toUpperCase();
    const volume = String(req.body.volume ?? '').trim();
    const side = String(req.body.side || req.body.orderType || '').trim().toLowerCase();

    if (!/^\d+$/.test(accountId)) {
        return res.status(400).json({
            success: false,
            message: 'A valid numeric accountId is required for Trader API position requests.'
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

        return res.json({
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
        return res.status(statusCode).json({
            success: false,
            message: error.response?.data?.message || error.message || 'Trade request failed via Exness.'
        });
    }
});

server.listen(PORT, '0.0.0.0', () => {
    console.log('============================================================');
    console.log(` L3 Markets Engine listening on port ${PORT}`);
    console.log(` Key Management Gateway URL: ${GATEWAY_URL || 'NOT SET'}`);
    console.log('============================================================');
});