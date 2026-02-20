const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Parse DATABASE_URL
function parseDatabaseUrl(url) {
    const result = { user: '', password: '', host: '', port: 5432, database: '' };
    const atIndex = url.indexOf('@');
    const protocolEnd = url.indexOf('://') + 3;
    const credentials = url.substring(protocolEnd, atIndex);
    const [user, password] = credentials.split(':');
    result.user = user;
    result.password = password;
    const afterAt = url.substring(atIndex + 1);
    const portIndex = afterAt.indexOf('/');
    const hostPort = afterAt.substring(0, portIndex);
    const colonIndex = hostPort.lastIndexOf(':');
    if (colonIndex > -1) {
        result.host = hostPort.substring(0, colonIndex);
        result.port = parseInt(hostPort.substring(colonIndex + 1));
    } else {
        result.host = hostPort;
    }
    result.database = afterAt.substring(portIndex + 1);
    return result;
}

const dbConfig = parseDatabaseUrl(process.env.DATABASE_URL);
const pool = new Pool({
    host: dbConfig.host,
    user: dbConfig.user,
    password: dbConfig.password,
    bank',
  port database: 'kod: dbConfig.port,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'kodbank_super_secret_key_2024_secure';

exports.handler = async function (event, context) {
    const headers = { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' };

    if (event.httpMethod === 'OPTIONS') {
        return { statusCode: 200, headers, body: '' };
    }

    try {
        // REGISTER
        if (event.path === '/api/register' && event.httpMethod === 'POST') {
            const { uid, username, password, email, phone } = JSON.parse(event.body);
            if (!uid || !username || !password || !email) {
                return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: 'Missing required fields' }) };
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            await pool.query('INSERT INTO KodUser (uid, username, email, password, balance, phone, role) VALUES ($1, $2, $3, $4, $5, $6, $7)', [uid, username, email, hashedPassword, 100000, phone || '', 'Customer']);
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, message: 'Registration successful!' }) };
        }

        // LOGIN
        if (event.path === '/api/login' && event.httpMethod === 'POST') {
            const { username, password } = JSON.parse(event.body);
            const users = await pool.query('SELECT * FROM KodUser WHERE username = $1', [username]);
            if (users.rows.length === 0) return { statusCode: 401, headers, body: JSON.stringify({ success: false, message: 'Invalid credentials' }) };
            const user = users.rows[0];
            const isValid = await bcrypt.compare(password, user.password);
            if (!isValid) return { statusCode: 401, headers, body: JSON.stringify({ success: false, message: 'Invalid credentials' }) };
            const token = jwt.sign({ username: user.username, role: user.role, uid: user.uid }, JWT_SECRET, { expiresIn: '24h' });
            const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
            await pool.query('INSERT INTO UserToken (token, uid, expiry) VALUES ($1, $2, $3)', [token, user.uid, expiry]);
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, token, user: { username: user.username, role: user.role, uid: user.uid } }) };
        }

        // BALANCE
        if (event.path === '/api/balance' && event.httpMethod === 'GET') {
            const token = event.headers.authorization?.split(' ')[1] || event.queryStringParameters?.token;
            if (!token) return { statusCode: 401, headers, body: JSON.stringify({ success: false, message: 'No token provided' }) };
            let decoded;
            try { decoded = jwt.verify(token, JWT_SECRET); }
            catch (err) { return { statusCode: 401, headers, body: JSON.stringify({ success: false, message: 'Invalid token' }) }; }
            const tokens = await pool.query('SELECT * FROM UserToken WHERE token = $1 AND uid = $2 AND expiry > NOW()', [token, decoded.uid]);
            if (tokens.rows.length === 0) return { statusCode: 401, headers, body: JSON.stringify({ success: false, message: 'Token expired' }) };
            const users = await pool.query('SELECT balance, username FROM KodUser WHERE uid = $1', [decoded.uid]);
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, balance: users.rows[0].balance, username: users.rows[0].username }) };
        }

        // LOGOUT
        if (event.path === '/api/logout' && event.httpMethod === 'POST') {
            const token = event.headers.authorization?.split(' ')[1];
            if (token) await pool.query('DELETE FROM UserToken WHERE token = $1', [token]);
            return { statusCode: 200, headers, body: JSON.stringify({ success: true }) };
        }

        // HEALTH CHECK
        if (event.path === '/api/health') {
            return { statusCode: 200, headers, body: JSON.stringify({ status: 'ok' }) };
        }

        return { statusCode: 404, headers, body: JSON.stringify({ error: 'Not found' }) };
    } catch (error) {
        return { statusCode: 500, headers, body: JSON.stringify({ error: error.message }) };
    }
};
