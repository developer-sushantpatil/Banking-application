const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Database config - use environment variable
const dbConfig = {
    host: process.env.DB_HOST || 'db.otviepliqleobakgqyda.supabase.co',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'Sushantkod114',
    database: process.env.DB_NAME || 'postgres',
    port: parseInt(process.env.DB_PORT) || 5432,
    ssl: { rejectUnauthorized: false }
};

const pool = new Pool(dbConfig);
const JWT_SECRET = process.env.JWT_SECRET || 'kodbank_super_secret_key_2024_secure';

exports.handler = async function (event, context) {
    const headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    };

    // Handle CORS preflight
    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    try {
        const path = event.path.replace('/.netlify/functions/api', '') || event.path;
        const method = event.httpMethod;

        // REGISTER
        if (path === '/api/register' && method === 'POST') {
            const { uid, username, password, email, phone } = JSON.parse(event.body);
            if (!uid || !username || !password || !email) {
                return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: 'Missing required fields' }) };
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            await pool.query(
                'INSERT INTO KodUser (uid, username, email, password, balance, phone, role) VALUES ($1, $2, $3, $4, $5, $6, $7)',
                [uid, username, email, hashedPassword, 100000, phone || '', 'Customer']
            );
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, message: 'Registration successful!' }) };
        }

        // LOGIN
        if (path === '/api/login' && method === 'POST') {
            const { username, password } = JSON.parse(event.body);
            const users = await pool.query('SELECT * FROM KodUser WHERE username = $1', [username]);
            if (users.rows.length === 0) {
                return { statusCode: 401, headers, body: JSON.stringify({ success: false, message: 'Invalid credentials' }) };
            }
            const user = users.rows[0];
            const isValid = await bcrypt.compare(password, user.password);
            if (!isValid) {
                return { statusCode: 401, headers, body: JSON.stringify({ success: false, message: 'Invalid credentials' }) };
            }
            const token = jwt.sign({ username: user.username, role: user.role, uid: user.uid }, JWT_SECRET, { expiresIn: '24h' });
            const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
            await pool.query('INSERT INTO UserToken (token, uid, expiry) VALUES ($1, $2, $3)', [token, user.uid, expiry]);
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, token, user: { username: user.username, role: user.role, uid: user.uid } }) };
        }

        // BALANCE
        if (path === '/api/balance' && method === 'GET') {
            const token = event.headers.authorization?.split(' ')[1] || event.queryStringParameters?.token;
            if (!token) {
                return { statusCode: 401, headers, body: JSON.stringify({ success: false, message: 'No token provided' }) };
            }
            let decoded;
            try { decoded = jwt.verify(token, JWT_SECRET); }
            catch (err) {
                return { statusCode: 401, headers, body: JSON.stringify({ success: false, message: 'Invalid token' }) };
            }
            const tokens = await pool.query('SELECT * FROM UserToken WHERE token = $1 AND uid = $2 AND expiry > NOW()', [token, decoded.uid]);
            if (tokens.rows.length === 0) {
                return { statusCode: 401, headers, body: JSON.stringify({ success: false, message: 'Token expired' }) };
            }
            const users = await pool.query('SELECT balance, username FROM KodUser WHERE uid = $1', [decoded.uid]);
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, balance: users.rows[0].balance, username: users.rows[0].username }) };
        }

        // LOGOUT
        if (path === '/api/logout' && method === 'POST') {
            const token = event.headers.authorization?.split(' ')[1];
            if (token) await pool.query('DELETE FROM UserToken WHERE token = $1', [token]);
            return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
        }

        // HEALTH CHECK
        if (path === '/api/health' || path === '/health') {
            return { statusCode: 200, headers, body: JSON.stringify({ status: 'ok' }) };
        }

        return { statusCode: 404, headers, body: JSON.stringify({ error: 'Not found', path, method }) };
    } catch (error) {
        console.error('Error:', error);
        return { statusCode: 500, headers, body: JSON.stringify({ error: error.message, stack: error.stack }) };
    }
};
