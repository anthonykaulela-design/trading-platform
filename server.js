/**
 * ============================================================================
 * L3 MARKETS - Exness Trader API Backend
 * All API keys, secrets, and base URLs are loaded strictly from .env
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
        broker: 'Exness Trader API',
        baseUrl: BASE_URL,
        discoveryBaseUrl: DISCOVERY_BASE_URL,
        accessPointUrl: resolvedAccessPointUrl || null,
        credentialsLoadedFromEnv: Boolean(EXNESS_API_KEY && EXNESS_SECRET_KEY),
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
    const accountId = String(req.body.accountId || req.body.account_id || DEFAULT_ACCOUNT_ID || '').trim();
    const apiKey = String(req.body.apiKey || req.body.api_key || EXNESS_API_KEY || '').trim();
    const secretKey = String(
        req.body.secretKey || req.body.secret_key || req.body.privateKey || EXNESS_SECRET_KEY || ''
    ).trim();

    if (!accountId) {
        return res.status(400).json({
            success: false,
            message: 'Exness Account ID is required.'
        });
    }

    if (!apiKey || !secretKey) {
        return res.status(400).json({
            success: false,
            message: 'Exness API Key and Secret/Private Key must be configured in .env or provided.'
        });
    }

    try {
        const discovery = await resolveAccessPoint(accountId, apiKey, secretKey);
        const targetHost = discovery.accessPoint;
        const accountPath = `/v1/trading/accounts/${encodeURIComponent(accountId)}`;
        const headers = createExnessAuthHeaders(apiKey, secretKey, 'GET', accountPath);

        let accountData = null;
        try {
            const accRes = await axios.get(`${targetHost}${accountPath}`, {
                headers,
                maxRedirects: 0,
                timeout: 10000
            });
            accountData = accRes.data;
        } catch (accErr) {
            console.warn('[L3 Markets Account Lookup]:', accErr.response?.status, accErr.response?.data || accErr.message);
        }

        const accountRecord = accountData
            ? {
                  login: accountData.login || accountData.account_id || accountId,
                  accountType: accountData.account_type || accountData.type || 'Exness Trader API',
                  currency: accountData.currency || 'USD',
                  balance: accountData.balance ?? 0,
                  equity: accountData.equity ?? accountData.balance ?? 0,
                  status: accountData.status || 'Connected'
              }
            : {
                  login: accountId,
                  accountType: 'Exness Trader API',
                  currency: 'USD',
                  balance: 0,
                  equity: 0,
                  status: 'Access Point Resolved'
              };

        res.json({
            success: true,
            platform: 'L3 Markets',
            token: `l3_exn_${crypto.randomBytes(16).toString('hex')}`,
            account_id: accountId,
            base_url: BASE_URL,
            access_point: targetHost,
            notice: 'All trades, positions, account balances, and market data are handled, processed, and kept directly by Exness.',
            accounts: [accountRecord]
        });
    } catch (error) {
        console.error('[L3 Markets Login Error]:', error.response?.status, error.response?.data || error.message);
        res.status(error.response?.status || 401).json({
            success: false,
            message:
                error.response?.data?.message ||
                'Exness authentication or access point discovery failed. Check your Account ID and .env credentials.'
        });
    }
});

app.post('/api/exness/refresh-session', async (req, res) => {
    const accountId = String(req.body.accountId || req.body.account_id || DEFAULT_ACCOUNT_ID || '').trim();
    if (!accountId) {
        return res.status(400).json({ success: false, message: 'account_id is required.' });
    }

    try {
        const discovery = await resolveAccessPoint(accountId);
        res.json({
            success: true,
            account_id: accountId,
            access_point: discovery.accessPoint,
            accounts: [
                {
                    login: accountId,
                    accountType: 'Exness Trader API',
                    currency: 'USD',
                    balance: 0,
                    equity: 0,
                    status: 'Active'
                }
            ]
        });
    } catch (error) {
        res.status(401).json({
            success: false,
            message: error.response?.data?.message || 'Session refresh failed.'
        });
    }
});

app.post('/api/exness/instruments', async (req, res) => {
    const accountId = String(req.body.accountId || req.body.account_id || DEFAULT_ACCOUNT_ID || '').trim();
    const targetHost = resolvedAccessPointUrl || BASE_URL;

    if (accountId && EXNESS_API_KEY && EXNESS_SECRET_KEY) {
        try {
            const pathAndQuery = `/v1/trading/instruments?account_id=${encodeURIComponent(accountId)}`;
            const headers = createExnessAuthHeaders(EXNESS_API_KEY, EXNESS_SECRET_KEY, 'GET', pathAndQuery);
            const response = await axios.get(`${targetHost}${pathAndQuery}`, {
                headers,
                maxRedirects: 0,
                timeout: 10000
            });
            return res.json({
                success: true,
                instruments: response.data?.instruments || response.data
            });
        } catch (err) {
            console.warn('[L3 Markets Instruments]:', err.response?.status, err.response?.data || err.message);
        }
    }

    return res.json({
        success: true,
        instruments: {
            forex_majors: [
                { symbol: 'EURUSD', name: 'Euro vs US Dollar', spread: 0.0001 },
                { symbol: 'GBPUSD', name: 'British Pound vs US Dollar', spread: 0.00014 },
                { symbol: 'USDJPY', name: 'US Dollar vs Japanese Yen', spread: 0.012 },
                { symbol: 'AUDUSD', name: 'Australian Dollar vs US Dollar', spread: 0.00012 }
            ],
            precious_metals: [
                { symbol: 'XAUUSD', name: 'Gold vs US Dollar', spread: 0.2 },
                { symbol: 'XAGUSD', name: 'Silver vs US Dollar', spread: 0.025 }
            ],
            cryptocurrencies: [
                { symbol: 'BTCUSD', name: 'Bitcoin vs US Dollar', spread: 12.0 },
                { symbol: 'ETHUSD', name: 'Ethereum vs US Dollar', spread: 1.5 }
            ],
            stock_indices: [
                { symbol: 'US30', name: 'Wall Street 30', spread: 2.2 },
                { symbol: 'USTEC', name: 'US Tech 100', spread: 1.5 }
            ]
        }
    });
});

app.post('/api/exness/trade', async (req, res) => {
    const accountId = String(req.body.accountId || req.body.account_id || DEFAULT_ACCOUNT_ID || '').trim();
    const { symbol, volume, orderType, price } = req.body;

    if (!accountId || !symbol || !volume || !orderType) {
        return res.status(400).json({
            success: false,
            message: 'accountId, symbol, volume, and orderType are required.'
        });
    }

    try {
        const discovery = await resolveAccessPoint(accountId);
        const orderPath = '/v1/trading/orders';
        const body = {
            account_id: accountId,
            symbol,
            volume,
            side: String(orderType).toLowerCase(),
            ...(price ? { price } : {})
        };
        const headers = createExnessAuthHeaders(EXNESS_API_KEY, EXNESS_SECRET_KEY, 'POST', orderPath, body);

        const orderRes = await axios.post(`${discovery.accessPoint}${orderPath}`, body, {
            headers,
            maxRedirects: 0,
            timeout: 10000
        });

        res.json({
            success: true,
            message: 'Order executed via Exness Trader API.',
            order: orderRes.data
        });
    } catch (error) {
        res.status(error.response?.status || 500).json({
            success: false,
            message: error.response?.data?.message || 'Trade execution failed.'
        });
    }
});

server.listen(PORT, '0.0.0.0', () => {
    console.log('============================================================');
    console.log(` L3 Markets Engine listening on port ${PORT}`);
    console.log(` Base URL: ${BASE_URL}`);
    console.log('============================================================');
});