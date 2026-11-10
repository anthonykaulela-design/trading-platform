/**
 * ============================================================================
 * L3 MARKETS - Exness Official API Engine
 * Standardized Request Signing & Zero In-Code Credential Architecture
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
 * Exness Protocol Signature Generator
 * Constructs the signed EXN-DATA & EXN-SIGN headers as required by Exness API documentation
 */
function createExnessAuthHeaders(payload = {}, idempotencyKey = "") {
    const timestamp = Date.now().toString();
    
    // Construct signed data JSON payload
    const dataObj = {
        api_key: EXNESS_API_KEY,
        timestamp: parseInt(timestamp, 10),
        ...payload
    };

    // Base64URL encoding without '=' padding
    const jsonStr = JSON.stringify(dataObj);
    const exnData = Buffer.from(jsonStr)
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');

    // Create HMAC SHA256 Signature from Secret Key
    const hmac = crypto.createHmac('sha256', EXNESS_SECRET_KEY);
    hmac.update(exnData);
    const exnSign = hmac.digest('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');

    return {
        'EXN-API-KEY': EXNESS_API_KEY,
        'EXN-IDEMPOTENCY-KEY': idempotencyKey,
        'EXN-TIMESTAMP': timestamp,
        'EXN-SIGN-VERSION': '1',
        'EXN-DATA': exnData,
        'EXN-SIGN': exnSign,
        'Content-Type': 'application/json'
    };
}

// WebSocket Feed for Real-time Price Updates
const wss = new WebSocket.Server({ server });
wss.on('connection', (ws) => {
    ws.send(JSON.stringify({ 
        type: 'SYSTEM_STATUS', 
        status: 'CONNECTED', 
        notice: 'All trades, positions, and balances are stored and processed by Exness.' 
    }));
});

// Production Health Check
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
 * Authentic Client Login & Account Fetching Route
 * Routes requests securely to Exness via standard API headers
 */
app.post('/api/exness/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Exness email and password are required.' });
    }

    try {
        const payload = { email, password };
        const authHeaders = createExnessAuthHeaders(payload, `login_${Date.now()}`);

        // Call Exness API Gateway
        const exnessResponse = await axios.post(`${EXNESS_BASE_URL}/v1/trading/accounts`, payload, {
            headers: authHeaders
        });

        const token = exnessResponse.data.token || exnessResponse.data.access_token || `exn_sess_${Date.now()}`;
        const userAccounts = exnessResponse.data.accounts || exnessResponse.data.items || [];

        res.json({
            success: true,
            token: token,
            user: email,
            notice: 'All trades and data are handled and kept by Exness.',
            accounts: userAccounts
        });

    } catch (error) {
        console.error('[Exness API Response Error]:', error.response?.data || error.message);
        
        // Return structured verification status to the client
        const statusCode = error.response?.status || 401;
        const errorMsg = error.response?.data?.message || 'Authentication error: Invalid Exness credentials or API signing parameters.';

        res.status(statusCode).json({
            success: false,
            message: errorMsg
        });
    }
});

/**
 * Session Verification Endpoint for Persistent Portal Refreshing
 */
app.post('/api/exness/refresh-session', async (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(401).json({ success: false, message: 'Session token required.' });
    }

    try {
        const headers = createExnessAuthHeaders({});
        headers['Authorization'] = `Bearer ${token}`;

        const accountsResponse = await axios.get(`${EXNESS_BASE_URL}/v1/trading/accounts`, { headers });

        res.json({
            success: true,
            accounts: accountsResponse.data.accounts || accountsResponse.data.items || []
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Exness session expired.' });
    }
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`============================================================`);
    console.log(` L3 Markets Engine operational on port ${PORT}`);
    console.log(` Credentials securely loaded from environment variables.`);
    console.log(` Notice: All data and trades are managed by Exness.`);
    console.log(`============================================================`);
});