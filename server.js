/**
 * ============================================================================
 * L3 MARKETS - Exness Backend Engine
 * Sign In with Email/Password • Exness Account, Trades, Quotes & Candlesticks
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
const EXNESS_API_KEY = process.env.EXNESS_API_KEY || '';
const EXNESS_SECRET_KEY = process.env.EXNESS_SECRET_KEY || process.env.EXNESS_PRIVATE_KEY || '';
const DEFAULT_ACCOUNT_ID = process.env.EXNESS_ACCOUNT_ID || '';

const BASE_URL = process.env.EXNESS_BASE_URL || 'https://api.exness.com';
const DISCOVERY_BASE_URL = process.env.EXNESS_DISCOVERY_BASE_URL || BASE_URL;
const ALT_BASE_URL = process.env.EXNESS_ALT_BASE_URL || '';

let resolvedAccessPointUrl = process.env.EXNESS_API_BASE_URL || '';

const app = express();
const server = http.createServer(app);

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

function toBase64Url(input) {
    return Buffer.from(input)
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

function createExnessAuthHeaders(apiKey, secretKey, method = 'POST', pathAndQuery = '', body = null) {
    const timestamp = Date.now().toString();
    const upperMethod = method.toUpperCase();
    const isGet = upperMethod === 'GET';
    const idempotencyKey = isGet ? '' : `l3_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;

    let bodyHash = '';
    if (!isGet && body !== null && body !== undefined) {
        const rawBody = typeof body === 'string' ? body : JSON.stringify(body);
        bodyHash = toBase64Url(crypto.createHash('sha256').update(rawBody).digest());
    }

    const payload = {
        api_key: apiKey,
        idempotency_key: idempotencyKey,
        timestamp: parseInt(timestamp, 10),
        sign_version: '1',
        method: upperMethod,
        path: pathAndQuery,
        body_hash: bodyHash
    };

    const exnData = toBase64Url(JSON.stringify(payload));
    const exnSign = toBase64Url(
        crypto.createHmac('sha256', secretKey).update(exnData).digest()
    );

    return {
        'EXN-API-KEY': apiKey,
        'EXN-IDEMPOTENCY-KEY': idempotencyKey,
        'EXN-TIMESTAMP': timestamp,
        'EXN-SIGN-VERSION': '1',
        'EXN-DATA': exnData,
        'EXN-SIGN': exnSign,
        'Content-Type': 'application/json'
    };
}

async function signedExnessGet(baseUrl, pathAndQuery) {
    const headers = createExnessAuthHeaders(EXNESS_API_KEY, EXNESS_SECRET_KEY, 'GET', pathAndQuery);
    return axios.get(`${baseUrl}${pathAndQuery}`, {
        headers,
        maxRedirects: 0,
        timeout: 10000
    });
}

async function resolveAccessPoint(accountId, apiKey = EXNESS_API_KEY, secretKey = EXNESS_SECRET_KEY) {
    const pathAndQuery = `/v1/trading/access-point?account_id=${encodeURIComponent(accountId)}`;
    const headers = createExnessAuthHeaders(apiKey, secretKey, 'GET', pathAndQuery);
    const hosts = [DISCOVERY_BASE_URL, BASE_URL, ALT_BASE_URL].filter(Boolean);
    const uniqueHosts = [...new Set(hosts)];

    let lastError = null;
    for (const host of uniqueHosts) {
        try {
            const response = await axios.get(`${host}${pathAndQuery}`, {
                headers,
                maxRedirects: 0,
                timeout: 10000
            });
            const accessPoint =
                response.data?.access_point ||
                response.data?.data?.access_point ||
                host;
            resolvedAccessPointUrl = accessPoint;
            return { accessPoint, hostUsed: host, raw: response.data };
        } catch (err) {
            lastError = err;
        }
    }

    throw lastError || new Error('Unable to resolve Exness access point.');
}

function normalizeCandles(rawPayload) {
    const list = Array.isArray(rawPayload)
        ? rawPayload
        : rawPayload?.candles || rawPayload?.bars || rawPayload?.ohlc || rawPayload?.items || rawPayload?.data || [];

    if (!Array.isArray(list)) return [];

    return list
        .map((c) => {
            const rawTime = c.x ?? c.time ?? c.timestamp ?? c.t ?? c.open_time ?? c.date;
            const ts = typeof rawTime === 'number'
                ? (rawTime < 1e12 ? rawTime * 1000 : rawTime)
                : Date.parse(rawTime);

            const o = Number(c.o ?? c.open);
            const h = Number(c.h ?? c.high);
            const l = Number(c.l ?? c.low);
            const closeVal = Number(c.c ?? c.close);

            if (!Number.isFinite(ts) || !Number.isFinite(o) || !Number.isFinite(h) || !Number.isFinite(l) || !Number.isFinite(closeVal)) {
                return null;
            }

            return { x: ts, o, h, l, c: closeVal };
        })
        .filter(Boolean)
        .sort((a, b) => a.x - b.x);
}

async function fetchExnessCandles(symbol, timeframe = '1m', limit = 100, accountId = DEFAULT_ACCOUNT_ID) {
    if (!EXNESS_API_KEY || !EXNESS_SECRET_KEY) {
        return { candles: [], source: 'missing_credentials' };
    }

    const cleanSymbol = String(symbol || 'EURUSD').trim().toUpperCase();
    const cleanTf = String(timeframe || '1m').trim();
    const cleanLimit = Math.min(Math.max(parseInt(limit, 10) || 100, 1), 1000);

    let host = resolvedAccessPointUrl || BASE_URL;
    if (accountId) {
        try {
            const disc = await resolveAccessPoint(accountId);
            host = disc.accessPoint;
        } catch (_) {}
    }

    const candidatePaths = [
        `/v1/trading/candles?symbol=${encodeURIComponent(cleanSymbol)}&timeframe=${encodeURIComponent(cleanTf)}&limit=${cleanLimit}${accountId ? `&account_id=${encodeURIComponent(accountId)}` : ''}`,
        `/v1/trading/instruments/${encodeURIComponent(cleanSymbol)}/candles?timeframe=${encodeURIComponent(cleanTf)}&limit=${cleanLimit}${accountId ? `&account_id=${encodeURIComponent(accountId)}` : ''}`,
        `/v1/trading/market-data/candles?symbol=${encodeURIComponent(cleanSymbol)}&resolution=${encodeURIComponent(cleanTf)}&limit=${cleanLimit}`
    ];

    const hostsToTry = [...new Set([host, BASE_URL, ALT_BASE_URL].filter(Boolean))];

    for (const targetHost of hostsToTry) {
        for (const pathAndQuery of candidatePaths) {
            try {
                const res = await signedExnessGet(targetHost, pathAndQuery);
                const candles = normalizeCandles(res.data);
                if (candles.length > 0) {
                    return { candles, source: 'exness', hostUsed: targetHost };
                }
            } catch (_) {}
        }
    }

    return { candles: [], source: 'exness_empty_or_unsupported_endpoint' };
}

async function fetchExnessAccountAndTrades(accountId, fallbackLabel = 'Exness Account') {
    let accountRecord = {
        login: accountId || fallbackLabel,
        accountType: 'Exness',
        currency: 'USD',
        balance: 0,
        equity: 0,
        margin: 0,
        freeMargin: 0,
        status: accountId ? 'Pending Exness Sync' : 'Set EXNESS_ACCOUNT_ID in .env'
    };

    let trades = [];
    let accessPoint = resolvedAccessPointUrl || BASE_URL;

    if (!accountId || !EXNESS_API_KEY || !EXNESS_SECRET_KEY) {
        return { account: accountRecord, trades, accessPoint };
    }

    try {
        const discovery = await resolveAccessPoint(accountId);
        accessPoint = discovery.accessPoint;

        const accountPath = `/v1/trading/accounts/${encodeURIComponent(accountId)}`;
        const accRes = await signedExnessGet(accessPoint, accountPath);

        const d = accRes.data?.data || accRes.data || {};
        const bal = Number(d.balance ?? 0);
        const eq = Number(d.equity ?? bal);

        accountRecord = {
            login: d.login || d.account_id || accountId,
            accountType: d.account_type || d.type || 'Exness Trader API',
            currency: d.currency || 'USD',
            balance: bal,
            equity: eq,
            margin: Number(d.margin ?? 0),
            freeMargin: Number(d.free_margin ?? d.freeMargin ?? Math.max(0, eq - Number(d.margin ?? 0))),
            status: d.status || 'Connected'
        };
    } catch (err) {
        console.warn('[L3 Markets Account Fetch]:', err.response?.status, err.response?.data || err.message);
        accountRecord.status = `Gateway Notice (${err.response?.status || 'Unreachable'})`;
    }

    try {
        const positionsPath = `/v1/trading/accounts/${encodeURIComponent(accountId)}/positions`;
        const posRes = await signedExnessGet(accessPoint, positionsPath);

        const rawList = Array.isArray(posRes.data)
            ? posRes.data
            : posRes.data?.positions || posRes.data?.trades || posRes.data?.items || [];

        trades = rawList.map((p, idx) => ({
            id: p.id || p.ticket || p.order_id || `POS-${idx + 1}`,
            symbol: p.symbol || 'EURUSD',
            side: String(p.side || p.type || 'buy').toUpperCase(),
            volume: Number(p.volume ?? p.lots ?? 0.01),
            openPrice: Number(p.open_price ?? p.openPrice ?? p.price ?? 0),
            profit: Number(p.profit ?? p.pnl ?? 0),
            status: p.status || 'OPEN'
        }));
    } catch (err) {
        console.warn('[L3 Markets Positions Fetch]:', err.response?.status, err.response?.data || err.message);
    }

    return { account: accountRecord, trades, accessPoint };
}

const wss = new WebSocket.Server({ server });
wss.on('connection', (ws) => {
    ws.send(
        JSON.stringify({
            type: 'SYSTEM_STATUS',
            platform: 'L3 Markets',
            status: 'CONNECTED',
            baseUrl: BASE_URL,
            accessPoint: resolvedAccessPointUrl || BASE_URL,
            notice: 'All trades, positions, account balances, and market data are handled, processed, and kept directly by Exness.'
        })
    );
});

app.get('/health', async (req, res) => {
    const accountId = String(req.query.account_id || DEFAULT_ACCOUNT_ID || '').trim();
    if (!resolvedAccessPointUrl && accountId && EXNESS_API_KEY && EXNESS_SECRET_KEY) {
        try {
            await resolveAccessPoint(accountId);
        } catch (err) {
            console.warn('[L3 Markets Health Discovery]:', err.response?.data || err.message);
        }
    }

    res.status(200).json({
        status: 'ONLINE',
        platform: 'L3 Markets',
        broker: 'Exness',
        baseUrl: BASE_URL,
        discoveryBaseUrl: DISCOVERY_BASE_URL,
        accessPointUrl: resolvedAccessPointUrl || null,
        accountConfigured: Boolean(DEFAULT_ACCOUNT_ID),
        credentialsLoadedFromEnv: Boolean(EXNESS_API_KEY && EXNESS_SECRET_KEY),
        notice: 'All trades, positions, account balances, and market data are handled, processed, and kept directly by Exness.',
        timestamp: new Date().toISOString()
    });
});

app.get('/api/exness/access-point', async (req, res) => {
    const accountId = String(req.query.account_id || DEFAULT_ACCOUNT_ID || '').trim();
    if (!accountId) {
        return res.status(400).json({ success: false, message: 'account_id is required.' });
    }

    try {
        const discovery = await resolveAccessPoint(accountId);
        res.json({
            success: true,
            account_id: accountId,
            access_point: discovery.accessPoint,
            host_used: discovery.hostUsed
        });
    } catch (error) {
        res.status(error.response?.status || 500).json({
            success: false,
            message: error.response?.data?.message || 'Failed to resolve Exness access point.'
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
    const synced = await fetchExnessAccountAndTrades(accountId, email);

    res.json({
        success: true,
        platform: 'L3 Markets',
        token: sessionToken,
        user: email,
        account_id: accountId || null,
        base_url: BASE_URL,
        access_point: synced.accessPoint,
        notice: 'All trades, positions, account balances, and market data are handled, processed, and kept directly by Exness.',
        accounts: [synced.account],
        trades: synced.trades
    });
});

app.post('/api/exness/refresh-session', async (req, res) => {
    const token = String(req.body.token || '').trim();
    const email = String(req.body.email || '').trim();
    const accountId = String(req.body.accountId || req.body.account_id || DEFAULT_ACCOUNT_ID || '').trim();

    if (!token) {
        return res.status(401).json({ success: false, message: 'Session token required.' });
    }

    const synced = await fetchExnessAccountAndTrades(accountId, email || 'Exness Account');

    res.json({
        success: true,
        user: email || null,
        account_id: accountId || null,
        base_url: BASE_URL,
        access_point: synced.accessPoint,
        accounts: [synced.account],
        trades: synced.trades
    });
});



app.get('/api/exness/debug-candles', async (req, res) => {
    const symbol = String(req.query.symbol || 'EURUSD').trim().toUpperCase();
    const timeframe = String(req.query.timeframe || '1m').trim();
    const accountId = String(req.query.account_id || DEFAULT_ACCOUNT_ID || '').trim();
    const host = resolvedAccessPointUrl || BASE_URL;

    const testPaths = [
        `/v1/trading/candles?symbol=${encodeURIComponent(symbol)}&timeframe=${encodeURIComponent(timeframe)}&limit=50${accountId ? `&account_id=${encodeURIComponent(accountId)}` : ''}`,
        `/v1/trading/instruments?account_id=${encodeURIComponent(accountId)}`
    ];

    const results = [];
    for (const pathAndQuery of testPaths) {
        try {
            const r = await signedExnessGet(host, pathAndQuery);
            results.push({ pathAndQuery, status: r.status, keys: Object.keys(r.data || {}), sample: r.data });
        } catch (err) {
            results.push({
                pathAndQuery,
                status: err.response?.status || 'ERR',
                error: err.response?.data || err.message
            });
        }
    }

    res.json({ host, accountConfigured: Boolean(accountId), results });
});
app.get('/api/exness/candles', async (req, res) => {
    const symbol = String(req.query.symbol || 'EURUSD').trim().toUpperCase();
    const timeframe = String(req.query.timeframe || '1m').trim();
    const limit = parseInt(req.query.limit, 10) || 100;
    const accountId = String(req.query.account_id || DEFAULT_ACCOUNT_ID || '').trim();

    const result = await fetchExnessCandles(symbol, timeframe, limit, accountId);

    res.json({
        success: true,
        symbol,
        timeframe,
        source: result.source,
        candles: result.candles
    });
});

app.post('/api/exness/instruments', async (req, res) => {
    const accountId = String(req.body.accountId || req.body.account_id || DEFAULT_ACCOUNT_ID || '').trim();
    const targetHost = resolvedAccessPointUrl || BASE_URL;

    if (accountId && EXNESS_API_KEY && EXNESS_SECRET_KEY) {
        try {
            const pathAndQuery = `/v1/trading/instruments?account_id=${encodeURIComponent(accountId)}`;
            const response = await signedExnessGet(targetHost, pathAndQuery);
            const raw = response.data?.instruments || response.data;
            if (raw && (Array.isArray(raw) ? raw.length > 0 : Object.keys(raw).length > 0)) {
                return res.json({
                    success: true,
                    source: 'exness',
                    instruments: raw
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
    const symbol = String(req.body.symbol || '').trim().toUpperCase();
    const volume = Number(req.body.volume);
    const side = String(req.body.side || req.body.orderType || '').trim().toLowerCase();
    const sl = req.body.sl !== undefined && req.body.sl !== '' ? Number(req.body.sl) : undefined;
    const tp = req.body.tp !== undefined && req.body.tp !== '' ? Number(req.body.tp) : undefined;

    if (!symbol || !Number.isFinite(volume) || volume <= 0 || !['buy', 'sell'].includes(side)) {
        return res.status(400).json({
            success: false,
            message: 'Valid symbol, positive volume, and side (buy or sell) are required.'
        });
    }

    if (!accountId || !EXNESS_API_KEY || !EXNESS_SECRET_KEY) {
        return res.status(400).json({
            success: false,
            message: 'EXNESS_ACCOUNT_ID and API credentials must be configured in .env for market execution.'
        });
    }

    try {
        const discovery = await resolveAccessPoint(accountId);
        const orderPath = '/v1/trading/orders';
        const body = {
            account_id: accountId,
            symbol,
            volume,
            side,
            order_type: 'market',
            ...(Number.isFinite(sl) ? { stop_loss: sl } : {}),
            ...(Number.isFinite(tp) ? { take_profit: tp } : {})
        };
        const headers = createExnessAuthHeaders(EXNESS_API_KEY, EXNESS_SECRET_KEY, 'POST', orderPath, body);

        const orderRes = await axios.post(`${discovery.accessPoint}${orderPath}`, body, {
            headers,
            maxRedirects: 0,
            timeout: 10000
        });

        const synced = await fetchExnessAccountAndTrades(accountId);

        res.json({
            success: true,
            message: `Market ${side.toUpperCase()} order for ${volume} ${symbol} submitted to Exness.`,
            order: orderRes.data,
            accounts: [synced.account],
            trades: synced.trades
        });
    } catch (error) {
        const statusCode = error.response?.status || 500;
        res.status(statusCode).json({
            success: false,
            message: error.response?.data?.message || 'Market trade execution failed via Exness.'
        });
    }
});

server.listen(PORT, '0.0.0.0', () => {
    console.log('============================================================');
    console.log(` L3 Markets Engine listening on port ${PORT}`);
    console.log(` Base URL: ${BASE_URL}`);
    console.log('============================================================');
});