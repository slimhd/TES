const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');
const forge = require('node-forge');
const sqlite3 = require('sqlite3').verbose();

// ============ LOAD .env FILE ============
function loadEnv() {
    const envPath = path.join(__dirname, '.env');
    if (fs.existsSync(envPath)) {
        const lines = fs.readFileSync(envPath, 'utf-8').split('\n');
        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith('#')) {
                const [key, ...valueParts] = trimmed.split('=');
                if (key && valueParts.length > 0) {
                    process.env[key.trim()] = valueParts.join('=').trim();
                }
            }
        }
        console.log('[Server] Loaded .env file');
    }
}
loadEnv();

// ============ CONFIG ============
const PORT = parseInt(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
// DB DES key for at-rest encryption (8 bytes hex = 16 chars)
const DB_DES_KEY = process.env.DB_DES_KEY || 'a1b2c3d4e5f67890';
const RSA_ROTATE_INTERVAL = 5 * 60 * 1000; // 5 minutes

// ============ DATABASE ============
const dbPath = path.join(__dirname, 'db', 'tes.db');
const db = new sqlite3.Database(dbPath);

// Initialize DB
const initSql = fs.readFileSync(path.join(__dirname, 'db', 'init.sql'), 'utf-8');
db.exec(initSql);

// ============ IN-MEMORY STORES ============
const sessions = new Map(); // sessionId -> { username, role }
const clientSessions = new Map(); // sessionId -> { desKey, iv }
let currentRSA = null;

// ============ RSA KEY MANAGEMENT ============
let rsaKeyVersion = 0;

function generateRSAKeyPair() {
    rsaKeyVersion++;
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
    const keyId = `${Date.now()}-v${rsaKeyVersion}`;
    currentRSA = {
        keyId,
        privateKey: keypair.privateKey,
        publicKey: keypair.publicKey,
        publicKeyPem: forge.pki.publicKeyToPem(keypair.publicKey),
        createdAt: Date.now()
    };
    console.log(`[RSA] Generated new key pair #${rsaKeyVersion}. Key ID: ${keyId}`);
    console.log(`[RSA] Next rotation in ${RSA_ROTATE_INTERVAL / 1000} seconds`);
    return currentRSA;
}

// Generate initial RSA keys
console.log('[RSA] Initializing RSA key pair...');
generateRSAKeyPair();

// Periodic RSA key rotation
const rotationTimer = setInterval(() => {
    console.log('[RSA] Periodic rotation triggered');
    generateRSAKeyPair();
    // Invalidate all client sessions on key rotation (they need to re-exchange)
    clientSessions.clear();
    console.log('[RSA] Cleared all client session keys');
}, RSA_ROTATE_INTERVAL);

console.log(`[RSA] Key rotation scheduled every ${RSA_ROTATE_INTERVAL / 1000} seconds`);

// ============ UTILITY FUNCTIONS ============
function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch (e) {
                resolve({});
            }
        });
        req.on('error', reject);
    });
}

function parseCookies(req) {
    const cookies = {};
    const header = req.headers.cookie || '';
    header.split(';').forEach(c => {
        const [k, v] = c.trim().split('=');
        if (k) cookies[k] = v;
    });
    return cookies;
}

function sendJSON(res, data, status = 200) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
}

function sendFile(res, filePath, contentType) {
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.writeHead(404);
            res.end('Not Found');
            return;
        }
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(data);
    });
}

function getSessionFromCookie(req) {
    const cookies = parseCookies(req);
    const sessionId = cookies.sessionId;
    if (sessionId && sessions.has(sessionId)) {
        return { sessionId, ...sessions.get(sessionId) };
    }
    return null;
}

// ============ PASSWORD HASHING ============
function hashPassword(password, salt) {
    return new Promise((resolve, reject) => {
        crypto.scrypt(password, salt, 64, (err, derived) => {
            if (err) reject(err);
            else resolve(derived.toString('hex'));
        });
    });
}

// ============ DES ENCRYPTION/DECRYPTION ============
function desEncrypt(plaintext, keyHex, ivHex) {
    const key = forge.util.hexToBytes(keyHex.slice(0, 16));
    const iv = forge.util.hexToBytes(ivHex.slice(0, 16));
    const cipher = forge.cipher.createCipher('DES-CBC', key);
    cipher.start({ iv });
    cipher.update(forge.util.createBuffer(plaintext, 'utf8'));
    cipher.finish();
    return forge.util.encode64(cipher.output.getBytes());
}

function desDecrypt(ciphertextB64, keyHex, ivHex) {
    const key = forge.util.hexToBytes(keyHex.slice(0, 16));
    const iv = forge.util.hexToBytes(ivHex.slice(0, 16));
    const decipher = forge.cipher.createDecipher('DES-CBC', key);
    decipher.start({ iv });
    decipher.update(forge.util.createBuffer(forge.util.decode64(ciphertextB64)));
    decipher.finish();
    return decipher.output.toString();
}

// ============ PENALTY CALCULATION ============
function calculatePenalty(speed) {
    if (speed >= 100) return 50;
    if (speed >= 70) return 20;
    if (speed >= 50) return 10;
    return 0;
}

// ============ HTTP SERVER ============
const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const method = req.method;

    // CORS headers for client
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Credentials', 'true');

    if (method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    // ============ STATIC FILES ============
    if (method === 'GET' && pathname === '/') {
        return sendFile(res, path.join(__dirname, 'public', 'login.html'), 'text/html');
    }
    if (method === 'GET' && pathname === '/login') {
        return sendFile(res, path.join(__dirname, 'public', 'login.html'), 'text/html');
    }
    if (method === 'GET' && pathname === '/officer') {
        const session = getSessionFromCookie(req);
        if (!session || session.role !== 'officer') {
            res.writeHead(302, { Location: '/login' });
            res.end();
            return;
        }
        return sendFile(res, path.join(__dirname, 'public', 'officer.html'), 'text/html');
    }
    if (method === 'GET' && pathname === '/style.css') {
        return sendFile(res, path.join(__dirname, 'public', 'style.css'), 'text/css');
    }

    // ============ AUTH API ============
    if (method === 'POST' && pathname === '/api/login') {
        const body = await parseBody(req);
        const { username, password } = body;

        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
            if (err || !user) {
                return sendJSON(res, { error: 'Invalid credentials' }, 401);
            }
            const hash = await hashPassword(password, user.salt);
            if (hash !== user.pass_hash) {
                return sendJSON(res, { error: 'Invalid credentials' }, 401);
            }
            const sessionId = crypto.randomBytes(16).toString('hex');
            sessions.set(sessionId, { username: user.username, role: user.role });
            res.setHeader('Set-Cookie', `sessionId=${sessionId}; Path=/; HttpOnly`);
            sendJSON(res, { success: true, role: user.role });
        });
        return;
    }

    if (method === 'POST' && pathname === '/api/logout') {
        const session = getSessionFromCookie(req);
        if (session) {
            sessions.delete(session.sessionId);
            clientSessions.delete(session.sessionId);
        }
        res.setHeader('Set-Cookie', 'sessionId=; Path=/; HttpOnly; Max-Age=0');
        return sendJSON(res, { success: true });
    }

    // ============ RSA API ============
    if (method === 'GET' && pathname === '/api/rsa/current') {
        return sendJSON(res, {
            key_id: currentRSA.keyId,
            public_key_pem: currentRSA.publicKeyPem,
            created_at: currentRSA.createdAt,
            version: rsaKeyVersion
        });
    }

    // Manual key rotation (for testing)
    if (method === 'POST' && pathname === '/api/rsa/rotate') {
        console.log('[RSA] Manual rotation requested');
        generateRSAKeyPair();
        clientSessions.clear();
        return sendJSON(res, { 
            success: true, 
            new_key_id: currentRSA.keyId,
            version: rsaKeyVersion
        });
    }

    // ============ SESSION KEY EXCHANGE ============
    if (method === 'POST' && pathname === '/api/session/exchange') {
        const cookies = parseCookies(req);
        const sessionId = cookies.sessionId;
        const session = sessions.get(sessionId);

        if (!session) {
            return sendJSON(res, { error: 'Not authenticated' }, 401);
        }

        const body = await parseBody(req);
        const { key_id, enc_session_key_b64, iv_b64 } = body;

        // Check key_id matches current
        if (key_id !== currentRSA.keyId) {
            return sendJSON(res, { error: 'Key expired', current_key_id: currentRSA.keyId }, 400);
        }

        try {
            // Decrypt session key with server's private RSA key
            const encBytes = forge.util.decode64(enc_session_key_b64);
            const decrypted = currentRSA.privateKey.decrypt(encBytes, 'RSA-OAEP');
            const desKeyHex = forge.util.bytesToHex(decrypted);

            // Store in client sessions
            clientSessions.set(sessionId, { desKey: desKeyHex, iv: iv_b64 });
            console.log(`[Session] Key exchange complete for ${session.username}`);
            return sendJSON(res, { success: true });
        } catch (e) {
            console.error('[Session] Key exchange failed:', e.message);
            return sendJSON(res, { error: 'Key exchange failed' }, 400);
        }
    }

    // ============ VIOLATION SUBMISSION (Police) ============
    if (method === 'POST' && pathname === '/api/violation') {
        const cookies = parseCookies(req);
        const sessionId = cookies.sessionId;
        const session = sessions.get(sessionId);

        if (!session || session.role !== 'police') {
            return sendJSON(res, { error: 'Unauthorized' }, 403);
        }

        const clientSession = clientSessions.get(sessionId);
        if (!clientSession) {
            return sendJSON(res, { error: 'No session key established' }, 400);
        }

        const body = await parseBody(req);
        const { iv_b64, ciphertext_b64, signature_b64, police_public_key_pem } = body;

        try {
            // 1. DES decrypt with session key
            const plaintext = desDecrypt(ciphertext_b64, clientSession.desKey, forge.util.bytesToHex(forge.util.decode64(iv_b64)));
            const data = JSON.parse(plaintext);

            // 2. Verify RSA signature
            const policePublicKey = forge.pki.publicKeyFromPem(police_public_key_pem);
            const md = forge.md.sha256.create();
            md.update(plaintext, 'utf8');
            const signatureBytes = forge.util.decode64(signature_b64);
            const verified = policePublicKey.verify(md.digest().bytes(), signatureBytes);

            if (!verified) {
                return sendJSON(res, { error: 'Invalid signature' }, 400);
            }

            // 3. Check if driver is registered
            const { plate, speed } = data;
            
            const driver = await new Promise((resolve, reject) => {
                db.get('SELECT id FROM drivers WHERE plate = ?', [plate], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });
            
            if (!driver) {
                return sendJSON(res, { error: `Driver with plate ${plate} is not registered` }, 400);
            }

            // 4. Compute penalty points
            const points = calculatePenalty(speed);

            if (points === 0) {
                return sendJSON(res, { error: 'Speed below threshold' }, 400);
            }

            // 5. Store as DES-encrypted message
            const ivForDb = crypto.randomBytes(8).toString('hex');
            const recordPlain = JSON.stringify({ plate, speed, points, ts: data.ts });
            const storedCiphertext = desEncrypt(recordPlain, DB_DES_KEY, ivForDb);

            db.run(
                'INSERT INTO violations (plate, speed, points, stored_ciphertext_b64, iv_b64) VALUES (?, ?, ?, ?, ?)',
                [plate, speed, points, storedCiphertext, ivForDb],
                function (err) {
                    if (err) {
                        console.error('[DB] Insert violation error:', err);
                        return sendJSON(res, { error: 'Database error' }, 500);
                    }
                    console.log(`[Violation] Recorded: ${plate}, speed=${speed}, points=${points}`);
                    sendJSON(res, { success: true, plate, speed, points });
                }
            );
        } catch (e) {
            console.error('[Violation] Processing error:', e.message);
            return sendJSON(res, { error: 'Processing failed' }, 400);
        }
        return;
    }

    // ============ DRIVER APIs (Officer) ============
    if (method === 'GET' && pathname === '/api/drivers') {
        const session = getSessionFromCookie(req);
        if (!session || session.role !== 'officer') {
            return sendJSON(res, { error: 'Unauthorized' }, 403);
        }
        db.all('SELECT id, plate, name FROM drivers', [], (err, rows) => {
            if (err) return sendJSON(res, { error: 'Database error' }, 500);
            sendJSON(res, { drivers: rows || [] });
        });
        return;
    }

    if (method === 'POST' && pathname === '/api/drivers') {
        const session = getSessionFromCookie(req);
        if (!session || session.role !== 'officer') {
            return sendJSON(res, { error: 'Unauthorized' }, 403);
        }
        const body = await parseBody(req);
        const { plate, name } = body;
        if (!plate || !name) {
            return sendJSON(res, { error: 'Plate and name required' }, 400);
        }
        db.run('INSERT INTO drivers (plate, name) VALUES (?, ?)', [plate.toUpperCase(), name], function (err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return sendJSON(res, { error: 'Plate already exists' }, 400);
                }
                return sendJSON(res, { error: 'Database error' }, 500);
            }
            sendJSON(res, { success: true, id: this.lastID });
        });
        return;
    }

    // ============ VIOLATIONS API (Officer) ============
    if (method === 'GET' && pathname === '/api/violations') {
        const session = getSessionFromCookie(req);
        if (!session || session.role !== 'officer') {
            return sendJSON(res, { error: 'Unauthorized' }, 403);
        }
        db.all('SELECT id, plate, speed, points, stored_ciphertext_b64, iv_b64, created_at FROM violations ORDER BY created_at DESC', [], (err, rows) => {
            if (err) return sendJSON(res, { error: 'Database error' }, 500);
            sendJSON(res, { violations: rows || [] });
        });
        return;
    }

    if (method === 'POST' && pathname === '/api/violations/decrypt') {
        const session = getSessionFromCookie(req);
        if (!session || session.role !== 'officer') {
            return sendJSON(res, { error: 'Unauthorized' }, 403);
        }
        const body = await parseBody(req);
        const { ciphertext_b64, iv_b64 } = body;
        try {
            const plaintext = desDecrypt(ciphertext_b64, DB_DES_KEY, iv_b64);
            sendJSON(res, { plaintext: JSON.parse(plaintext) });
        } catch (e) {
            sendJSON(res, { error: 'Decryption failed' }, 400);
        }
        return;
    }

    // ============ 404 ============
    res.writeHead(404);
    res.end('Not Found');
});

server.listen(PORT, HOST, () => {
    console.log(`\n========================================`);
    console.log(`[TES Server] Running on http://${HOST}:${PORT}`);
    console.log(`[TES Server] Current RSA Key ID: ${currentRSA.keyId}`);
    console.log(`[TES Server] RSA rotation interval: ${RSA_ROTATE_INTERVAL / 1000}s (${RSA_ROTATE_INTERVAL / 60000} min)`);
    console.log(`[TES Server] Manual rotation: POST /api/rsa/rotate`);
    console.log(`========================================\n`);
});

