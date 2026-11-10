/**
 * ============================================================================
 * L3 MARKETS - Production Exness API Engine (Zero Simulation)
 * ============================================================================
 */

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const http = require('http');
const WebSocket = require('ws');
require('dotenv').config();

const PORT = process.env.PORT || 10000;
const EXNESS_API_KEY = process.env.EXNESS_API_KEY;
const EXNESS_SECRET_KEY = process.env.EXNESS_SECRET_KEY;
const EXNESS_BASE_URL = 'https://api.exness.com';

const app = express();
const server = http.createServer(app);

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
    ws.send(JSON.stringify({ 
        type: 'SYSTEM_STATUS', 
        status: 'CONNECTED', 
        notice: 'All trades, account management, and financial data are handled, processed, and kept directly by Exness.' 
    }));
});

// Production Health Endpoint
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'ONLINE',
        broker: 'Exness',
        notice: 'All trades and data are handled and kept by Exness.',
        timestamp: new Date().toISOString()
    });
});

// Real Production Exness Login & Account Retrieval Route
app.post('/api/exness/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'Exness email and password are required.' });
    }

    try {
        // Authenticate client directly against Exness API Gateway
        const exnessResponse = await axios.post(`${EXNESS_BASE_URL}/v1/auth/login`, {
            email: email,
            password: password
        }, {
            headers: {
                'X-API-KEY': EXNESS_API_KEY,
                'X-SECRET-KEY': EXNESS_SECRET_KEY,
                'Content-Type': 'application/json'
            }
        });

        const token = exnessResponse.data.access_token || exnessResponse.data.token;

        // Fetch user's live trading accounts directly from Exness
        const accountsResponse = await axios.get(`${EXNESS_BASE_URL}/v1/accounts`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'X-API-KEY': EXNESS_API_KEY
            }
        });

        res.json({
            success: true,
            token: token,
            user: email,
            notice: 'All trades and data are handled and kept by Exness.',
            accounts: accountsResponse.data.accounts || accountsResponse.data
        });

    } catch (error) {
        console.error('[Exness API Error]:', error.response?.data || error.message);
        res.status(error.response?.status || 500).json({
            success: false,
            message: error.response?.data?.message || 'Failed to authenticate with Exness servers. Please check your credentials.'
        });
    }
});

// Real Production Account Refresh Endpoint for Session Persistence
app.post('/api/exness/refresh-session', async (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(401).json({ success: false, message: 'Session token required.' });
    }

    try {
        const accountsResponse = await axios.get(`${EXNESS_BASE_URL}/v1/accounts`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'X-API-KEY': EXNESS_API_KEY
            }
        });

        res.json({
            success: true,
            accounts: accountsResponse.data.accounts || accountsResponse.data
        });
    } catch (error) {
        res.status(401).json({ success: false, message: 'Session expired or invalid.' });
    }
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`L3 Markets Production Server Engine running on port ${PORT}`);
});