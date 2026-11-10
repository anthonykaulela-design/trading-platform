/**
 * ============================================================================
 * L3 MARKETS - Production Exness API Engine (Zero Simulation)
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

const wss = new WebSocket.Server({ server });
wss.on('connection', (ws) => {
    ws.send(JSON.stringify({ 
        type: 'SYSTEM_STATUS', 
        status: 'CONNECTED', 
        notice: 'All trades, positions, and balances are handled and kept by Exness.' 
    }));
});

app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'ONLINE',
        broker: 'Exness',
        notice: 'All trades and data are handled and kept by Exness.',
        credentialsLoaded: !!(EXNESS_API_KEY && EXNESS_SECRET_KEY),
        timestamp: new Date().toISOString()
    });
});

// Strict production login routing — zero simulation fallbacks
app.post('/api/exness/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Exness email and password are required.' });
    }

    try {
        const payload = { email, password };
        const authHeaders = createExnessAuthHeaders(payload, `login_${Date.now()}`);

        const exnessResponse = await axios.post(`${EXNESS_BASE_URL}/v1/client/accounts`, payload, {
            headers: authHeaders,
            timeout: 10000
        });

        res.json({
            success: true,
            token: exnessResponse.data.token || exnessResponse.data.access_token,
            user: email,
            notice: 'All trades and data are handled and kept by Exness.',
            accounts: exnessResponse.data.accounts || exnessResponse.data.items || []
        });

    } catch (error) {
        console.error('[Exness API Error]:', error.response?.status, error.response?.data || error.message);
        
        const statusCode = error.response?.status || 401;
        const errorMsg = error.response?.data?.message || 'Authentication failed against Exness live gateway.';

        res.status(statusCode).json({
            success: false,
            message: errorMsg
        });
    }
});

app.post('/api/exness/refresh-session', async (req, res) => {
    const { token, email } = req.body;

    if (!token) {
        return res.status(401).json({ success: false, message: 'Session token required.' });
    }

    try {
        const headers = createExnessAuthHeaders({ email });
        headers['Authorization'] = `Bearer ${token}`;

        const accountsResponse = await axios.get(`${EXNESS_BASE_URL}/v1/client/accounts`, { headers });

        res.json({
            success: true,
            accounts: accountsResponse.data.accounts || accountsResponse.data.items || []
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Exness session expired.' });
    }
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`L3 Markets Production Engine active on port ${PORT}`);
});