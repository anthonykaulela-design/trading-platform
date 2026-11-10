/**
 * ============================================================================
 * L3 MARKETS - Official Exness API & Partner Gateway Engine
 * Production Mode • Zero Simulation • Full API Integration
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
const EXNESS_AFFILIATE_URL = 'https://my.exnessaffiliates.com';

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

    const hmac = crypto.createHmac('sha256', EXNESS_SECRET_KEY || 'l3_secure');
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

// WebSocket real-time broadcast server
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
 * 1. Fetch Live Symbols & Markets Directly from Exness API Catalog
 */
app.get('/api/exness/instruments', async (req, res) => {
    try {
        const response = await axios.get(`${EXNESS_BASE_URL}/v1/trading/symbols`, {
            headers: createExnessAuthHeaders({})
        });
        res.json({ success: true, instruments: response.data.symbols || response.data });
    } catch (error) {
        // Fallback dynamic query to Exness partner schema if standard symbol endpoint requires direct user token
        try {
            const fallbackRes = await axios.get(`${EXNESS_BASE_URL}/v1/markets/instruments`, {
                headers: createExnessAuthHeaders({})
            });
            res.json({ success: true, instruments: fallbackRes.data });
        } catch (err) {
            res.status(500).json({ 
                success: false, 
                message: 'Failed to fetch live instrument catalog from Exness API. Verify environment keys.' 
            });
        }
    }
});

/**
 * 2. Authentic Client Login (Credentials Authentication via Exness API)
 */
app.post('/api/exness/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Exness email and password are required.' });
    }

    try {
        const payload = { email, password };
        const authHeaders = createExnessAuthHeaders(payload, `login_${Date.now()}`);

        // Authenticate against Exness Partner/Client API Gateway
        const exnessResponse = await axios.post(`${EXNESS_AFFILIATE_URL}/api/auth`, payload, {
            headers: authHeaders,
            timeout: 10000
        });

        const token = exnessResponse.data.token || exnessResponse.data.access_token;

        // Fetch true client account details and exact balances using the obtained bearer token
        const accountsResponse = await axios.get(`${EXNESS_BASE_URL}/v1/clients/accounts`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'EXN-API-KEY': EXNESS_API_KEY
            }
        });

        res.json({
            success: true,
            token: token,
            user: email,
            notice: 'All trades and data are handled and kept by Exness.',
            accounts: accountsResponse.data.accounts || accountsResponse.data.items || []
        });

    } catch (error) {
        console.error('[Exness API Auth Error]:', error.response?.data || error.message);
        res.status(401).json({
            success: false,
            message: error.response?.data?.message || 'Exness API authentication failed. Invalid credentials or API restrictions.'
        });
    }
});

/**
 * 3. Session Refresh & Balance Synchronization
 */
app.post('/api/exness/refresh-session', async (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(401).json({ success: false, message: 'Session token required.' });
    }

    try {
        const accountsResponse = await axios.get(`${EXNESS_BASE_URL}/v1/clients/accounts`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'EXN-API-KEY': EXNESS_API_KEY
            }
        });

        res.json({
            success: true,
            accounts: accountsResponse.data.accounts || accountsResponse.data.items || []
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Exness session expired.' });
    }
});

/**
 * 4. Place Trade & Order Management Managed by Exness API
 */
app.post('/api/exness/trade', async (req, res) => {
    const { token, symbol, volume, orderType, price } = req.body;

    if (!token || !symbol || !volume || !orderType) {
        return res.status(400).json({ success: false, message: 'Missing order execution parameters.' });
    }

    try {
        const payload = { symbol, volume, orderType, price };
        const headers = createExnessAuthHeaders(payload, `order_${Date.now()}`);
        headers['Authorization'] = `Bearer ${token}`;

        const orderResponse = await axios.post(`${EXNESS_BASE_URL}/v1/trading/orders`, payload, { headers });

        res.json({
            success: true,
            message: 'Trade executed successfully through Exness API.',
            order: orderResponse.data
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.response?.data?.message || 'Trade execution failed via Exness gateway.' });
    }
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`============================================================`);
    console.log(` L3 Markets Production Engine active on port ${PORT}`);
    console.log(` Mode: 100% Exness API Driven (Zero Simulation)`);
    console.log(`============================================================`);
});