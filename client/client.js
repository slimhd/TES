const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const forge = require('node-forge');

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
        console.log('[Client] Loaded .env file');
    }
}
loadEnv();

// ============ CONFIG ============
const CLIENT_PORT = parseInt(process.env.CLIENT_PORT) || 3001;
const SERVER_URL = process.env.SERVER_URL || 'http://localhost:3000';

// Parse server URL
const serverParsed = new URL(SERVER_URL);
const SERVER_HOST = serverParsed.hostname;
const SERVER_PORT = parseInt(serverParsed.port) || 80;

// ============ LOAD POLICE RSA KEYS ============
const keysDir = path.join(__dirname, 'keys');
let policePrivateKey, policePublicKey, policePublicKeyPem;

try {
    const privatePem = fs.readFileSync(path.join(keysDir, 'police_private.pem'), 'utf-8');
    const publicPem = fs.readFileSync(path.join(keysDir, 'police_public.pem'), 'utf-8');
    policePrivateKey = forge.pki.privateKeyFromPem(privatePem);
    policePublicKey = forge.pki.publicKeyFromPem(publicPem);
    policePublicKeyPem = publicPem;
    console.log('[Client] Loaded police RSA keys');
} catch (err) {
    console.log('[Client] Generating new police RSA keys...');
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
    policePrivateKey = keypair.privateKey;
    policePublicKey = keypair.publicKey;
    policePublicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
    
    // Save keys
    if (!fs.existsSync(keysDir)) {
        fs.mkdirSync(keysDir, { recursive: true });
    }
    fs.writeFileSync(path.join(keysDir, 'police_private.pem'), forge.pki.privateKeyToPem(keypair.privateKey));
    fs.writeFileSync(path.join(keysDir, 'police_public.pem'), policePublicKeyPem);
    console.log('[Client] Saved new police RSA keys to keys/');
}

// ============ CLIENT STATE ============
let sessionCookie = null;
let sessionDesKey = null;
let sessionIv = null;
let serverRsaPublicKey = null;
let serverKeyId = null;

// ============ HTTP HELPERS ============
function makeRequest(options, body = null) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                // Capture set-cookie header
                const setCookie = res.headers['set-cookie'];
                if (setCookie) {
                    const match = setCookie[0].match(/sessionId=([^;]+)/);
                    if (match) sessionCookie = match[1];
                }
                try {
                    resolve({ status: res.statusCode, data: JSON.parse(data), headers: res.headers });
                } catch {
                    resolve({ status: res.statusCode, data, headers: res.headers });
                }
            });
        });
        req.on('error', reject);
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

function apiRequest(method, path, body = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (sessionCookie) {
        headers['Cookie'] = `sessionId=${sessionCookie}`;
    }
    return makeRequest({
        hostname: SERVER_HOST,
        port: SERVER_PORT,
        path,
        method,
        headers
    }, body);
}

// ============ DES ENCRYPTION ============
function desEncrypt(plaintext, keyHex, ivHex) {
    const key = forge.util.hexToBytes(keyHex.slice(0, 16));
    const iv = forge.util.hexToBytes(ivHex.slice(0, 16));
    const cipher = forge.cipher.createCipher('DES-CBC', key);
    cipher.start({ iv });
    cipher.update(forge.util.createBuffer(plaintext, 'utf8'));
    cipher.finish();
    return forge.util.encode64(cipher.output.getBytes());
}

// ============ RSA OPERATIONS ============
async function fetchServerRsaKey() {
    const res = await apiRequest('GET', '/api/rsa/current');
    if (res.status === 200 && res.data.public_key_pem) {
        serverRsaPublicKey = forge.pki.publicKeyFromPem(res.data.public_key_pem);
        serverKeyId = res.data.key_id;
        console.log(`[Client] Got server RSA key. Key ID: ${serverKeyId}`);
        return true;
    }
    console.error('[Client] Failed to fetch server RSA key');
    return false;
}

async function performKeyExchange() {
    // Generate random DES key (8 bytes) and IV (8 bytes)
    sessionDesKey = forge.util.bytesToHex(forge.random.getBytesSync(8));
    sessionIv = forge.util.bytesToHex(forge.random.getBytesSync(8));
    
    // Encrypt DES key with server's RSA public key
    const desKeyBytes = forge.util.hexToBytes(sessionDesKey);
    const encrypted = serverRsaPublicKey.encrypt(desKeyBytes, 'RSA-OAEP');
    const encB64 = forge.util.encode64(encrypted);
    
    const res = await apiRequest('POST', '/api/session/exchange', {
        key_id: serverKeyId,
        enc_session_key_b64: encB64,
        iv_b64: forge.util.encode64(forge.util.hexToBytes(sessionIv))
    });
    
    if (res.status === 200 && res.data.success) {
        console.log('[Client] Key exchange successful');
        return true;
    }
    
    // Key might have expired, refetch
    if (res.data.error === 'Key expired') {
        console.log('[Client] Key expired, refetching...');
        await fetchServerRsaKey();
        return performKeyExchange();
    }
    
    console.error('[Client] Key exchange failed:', res.data.error);
    return false;
}

// ============ SEND VIOLATION ============
async function sendViolation(plate, speed) {
    if (speed < 50) {
        return { success: false, error: 'Speed below 50 km/h - not sending' };
    }
    
    if (!sessionDesKey) {
        return { success: false, error: 'No session key - login first' };
    }
    
    // Build plaintext
    const plaintext = JSON.stringify({ plate: plate.toUpperCase(), speed, ts: new Date().toISOString() });
    
    // Sign plaintext with police private key
    const md = forge.md.sha256.create();
    md.update(plaintext, 'utf8');
    const signature = policePrivateKey.sign(md);
    const signatureB64 = forge.util.encode64(signature);
    
    // Encrypt with DES
    const ivBytes = forge.random.getBytesSync(8);
    const ivHex = forge.util.bytesToHex(ivBytes);
    const ciphertextB64 = desEncrypt(plaintext, sessionDesKey, ivHex);
    
    const res = await apiRequest('POST', '/api/violation', {
        iv_b64: forge.util.encode64(ivBytes),
        ciphertext_b64: ciphertextB64,
        signature_b64: signatureB64,
        police_public_key_pem: policePublicKeyPem
    });
    
    if (res.status === 200 && res.data.success) {
        return { success: true, data: res.data };
    }
    return { success: false, error: res.data.error || 'Failed to send violation' };
}

// ============ SIMPLE HTTP UI SERVER ============
const uiServer = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const method = req.method;
    
    // Serve HTML UI
    if (method === 'GET' && pathname === '/') {
        const html = fs.readFileSync(path.join(__dirname, 'police.html'), 'utf-8');
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(html);
        return;
    }
    
    // API: Login
    if (method === 'POST' && pathname === '/api/login') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { username, password } = JSON.parse(body);
                const loginRes = await apiRequest('POST', '/api/login', { username, password });
                
                if (loginRes.status === 200 && loginRes.data.success) {
                    // Fetch RSA key and do key exchange
                    await fetchServerRsaKey();
                    await performKeyExchange();
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, role: loginRes.data.role }));
                } else {
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: loginRes.data.error || 'Login failed' }));
                }
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }
    
    // API: Send violation
    if (method === 'POST' && pathname === '/api/send') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { plate, speed } = JSON.parse(body);
                const result = await sendViolation(plate, parseInt(speed));
                res.writeHead(result.success ? 200 : 400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(result));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: err.message }));
            }
        });
        return;
    }
    
    // API: Status
    if (method === 'GET' && pathname === '/api/status') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            loggedIn: !!sessionCookie,
            hasSessionKey: !!sessionDesKey,
            serverKeyId
        }));
        return;
    }
    
    // API: Logout
    if (method === 'POST' && pathname === '/api/logout') {
        // Call server logout
        await apiRequest('POST', '/api/logout');
        // Clear local session state
        sessionCookie = null;
        sessionDesKey = null;
        sessionIv = null;
        serverRsaPublicKey = null;
        serverKeyId = null;
        console.log('[Client] Logged out');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
        return;
    }
    
    res.writeHead(404);
    res.end('Not Found');
});

uiServer.listen(CLIENT_PORT, () => {
    console.log(`[Police Client] UI running on http://localhost:${CLIENT_PORT}`);
    console.log(`[Police Client] Server URL: ${SERVER_URL}`);
});

