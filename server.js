/**
 * ============================================================================
 * L3 MARKETS - Official Exness API Trading & Data Proxy Engine
 * Zero Simulation • Direct Exness REST & WebSocket API Integration
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
const EXNESS_API_KEY = process.env.EXNESS_API_KEY;
const EXNESS_SECRET_KEY = process.env.EXNESS_SECRET_KEY;
const EXNESS_BASE_URL = process.env.EXNESS_BASE_URL || 'https://api.exness.com';

const app = express();
const server = http.createServer(app);

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

/**
 * Exness HMAC-SHA256 Request Signing Protocol
 */
function createExnessAuthHeaders(payload = {}, idempotencyKey = "") {
    const timestamp = Date.now().toString();
    const dataObj = {
        api_key: EXNESS_API_KEY,
        timestamp: parseInt(timestamp, 10),
        ...payload
    };

    const jsonStr = JSON.stringify(dataObj);
    const exnData = Buffer.from(jsonStr)
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');

    const hmac = crypto.createHmac('sha256', EXNESS_SECRET_KEY);
    hmac.update(exnData);
    const exnSign = hmac.digest('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');

    return {
        'EXN-API-KEY': EXNESS_API_KEY,
        'EXN-IDEMPOTENCY-KEY': idempotencyKey || `req_${Date.now()}`,
        'EXN-TIMESTAMP': timestamp,
        'EXN-SIGN-VERSION': '1',
        'EXN-DATA': exnData,
        'EXN-SIGN': exnSign,
        'Content-Type': 'application/json'
    };
}

// WebSocket proxy for live market feeds direct from Exness
const wss = new WebSocket.Server({ server });
wss.on('connection', (ws) => {
    ws.send(JSON.stringify({ 
        type: 'SYSTEM_STATUS', 
        status: 'CONNECTED', 
        notice: 'All trades, positions, account balances, and market data are handled, processed, and kept securely by Exness.' 
    }));
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'ONLINE',
        broker: 'Exness',
        notice: 'All trades and data are handled and kept by Exness.',
        credentialsLoaded: !!(EXNESS_API_KEY && EXNESS_SECRET_KEY),
        timestamp: new Date().toISOString()
    });
});

/**
 * 1. Fetch All Trading Symbols, Commodities, Indices, Metals & Crypto directly from Exness API
 */
app.get('/api/exness/symbols', async (req, res) => {
    try {
        const headers = createExnessAuthHeaders({});
        const response = await axios.get(`${EXNESS_BASE_URL}/v1/trading/symbols`, { headers, timeout: 8000 });
        res.json({ success: true, symbols: response.data.symbols || response.data.items || [] });
    } catch (error) {
        console.error('[Exness Symbols API Error]:', error.response?.data || error.message);
        res.status(500).json({ success: false, message: 'Failed to fetch symbols from Exness API.' });
    }
});

/**
 * 2. Fetch Live Candlesticks & Chart Data directly from Exness API
 */
app.get('/api/exness/candles/:symbol', async (req, res) => {
    const { symbol } = req.params;
    const { timeframe = '1m', limit = '50' } = req.query;

    try {
        const headers = createExnessAuthHeaders({ symbol, timeframe, limit });
        const response = await axios.get(`${EXNESS_BASE_URL}/v1/market/candles`, {
            params: { symbol, timeframe, limit },
            headers,
            timeout: 8000
        });
        res.json({ success: true, candles: response.data.candles || response.data.items || [] });
    } catch (error) {
        console.error('[Exness Candles API Error]:', error.response?.data || error.message);
        res.status(500).json({ success: false, message: 'Failed to fetch candlestick data from Exness API.' });
    }
});

/**
 * 3. Authenticate Client & Fetch Exact Account Balances and Account IDs via Exness API
 */
app.post('/api/exness/login', async (req, res) => {
    const { apiKey, apiSecret, accountId, isDemo } = req.body;

    if (!apiKey || !accountNumber) {
        // Fallback to primary API keys in env if user provides Exness account credentials
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Exness API credentials or account details required.' });
        }
    }

    try {
        const payload = { accountId, isDemo: !!isDemo };
        const headers = createExnessAuthHeaders(payload, `auth_${Date.now()}`);

        const response = await axios.post(`${EXNESS_BASE_URL}/v1/trading/accounts`, payload, {
            headers,
            timeout: 10000
        });

        res.json({
            success: true,
            token: response.data.token || response.data.access_token || `exn_sess_${Date.now()}`,
            accounts: response.data.accounts || response.data.items || []
        });
    } catch (error) {
        console.error('[Exness Auth API Error]:', error.response?.data || error.message);
        res.status(error.response?.status || 401).json({
            success: false,
            message: error.response?.data?.message || 'Exness API authentication failed.'
        });
    }
});

/**
 * 4. Place and Manage Trades directly through Exness Trading API
 */
app.post('/api/exness/trade', async (req, res) => {
    const { accountId, symbol, volume, orderType, price, stopLoss, takeProfit } = req.body;

    if (!accountId || !symbol || !volume || !orderType) {
        return res.status(400).json({ success: false, message: 'Missing required order execution parameters.' });
    }

    try {
        const payload = { accountId, symbol, volume, orderType, price, stopLoss, takeProfit };
        const headers = createExnessAuthHeaders(payload, `order_${Date.now()}`);

        const response = await axios.post(`${EXNESS_BASE_URL}/v1/trading/orders`, payload, {
            headers,
            timeout: 10000
        });

        res.json({
            success: true,
            notice: 'All trades and executions are managed and kept directly by Exness.',
            order: response.data
        });
    } catch (error) {
        console.error('[Exness Trade Execution Error]:', error.response?.data || error.message);
        res.status(500).json({
            success: false,
            message: error.response?.data?.message || 'Trade execution rejected by Exness API.'
        });
    }
});

/**
 * 5. Session Refresh & Balance Synchronization
 */
app.post('/api/exness/refresh-session', async (req, res) => {
    const { token, accountId } = req.body;

    if (!token) {
        return res.status(401).json({ success: false, message: 'Session token required.' });
    }

    try {
        const headers = createExnessAuthHeaders({ accountId });
        headers['Authorization'] = `Bearer ${token}`;

        const response = await axios.get(`${EXNESS_BASE_URL}/v1/trading/accounts`, { headers });

        res.json({
            success: true,
            accounts: response.data.accounts || response.data.items || []
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Exness session expired.' });
    }
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`============================================================`);
    console.log(` L3 Markets Exness API Engine active on port ${PORT}`);
    console.log(` Notice: All data and trades are managed by Exness.`);
    console.log(`============================================================`);
});