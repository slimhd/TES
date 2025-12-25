# Traffic Enforcement System (TES)

CMSE-456/CMPE-455 Term Project - Minimal Implementation

## Quick Start (After Cloning)

### Prerequisites
- Node.js (v14 or higher)

### Step 1: Install Dependencies

```bash
# Server
cd tes-min/server
npm install

# Client
cd ../client
npm install
```

### Step 2: Create Users (Server)

```bash
cd tes-min/server

# Create an officer user
node scripts/createUser.js --role officer --username officer1 --password officer123

# Create a police user
node scripts/createUser.js --role police --username police1 --password police123
```

### Step 3: Start the Server

```bash
cd tes-min/server
node server.js
```

Server runs on `http://localhost:3000`

### Step 4: Start the Client

**Same computer (testing):**
```bash
cd tes-min/client
node client.js
```

**Different computer (LAN):**
```bash
cd tes-min/client

# Windows PowerShell - set server IP first
copy example.env .env
# Edit .env and set SERVER_URL=http://<SERVER_IP>:3000

node client.js
```

Client UI runs on `http://localhost:3001`

### Step 5: Test It

1. **Officer** (http://localhost:3000):
   - Login with `officer1` / `officer123`
   - Register 3 drivers (e.g., ABC123, XYZ789, TEST01)

2. **Police** (http://localhost:3001):
   - Login with `police1` / `police123`
   - Enter a registered plate + speed >= 50
   - Click "Send Encrypted Violation"

3. **Officer**: Refresh to see violations under each driver

---

## Overview

Two-computer system:
- **Server (Traffic Officer)**: Manages drivers, receives violations, stores encrypted records
- **Client (Traffic Police)**: Sends DES-encrypted, digitally signed violation reports

## Features

- DES encryption for message transmission
- RSA digital signatures for message authentication
- RSA session key exchange
- Periodic RSA key rotation (every 5 minutes)
- Password hashing with scrypt (salted)
- SQLite database storage
- At-rest encryption for violation records

## Penalty Rules

| Speed (km/h) | Penalty Points |
|--------------|----------------|
| 50 - 69      | 10             |
| 70 - 99      | 20             |
| >= 100       | 50             |

*Speeds below 50 km/h are not sent.*

---

## Two-Computer Setup (LAN)

### Server Computer (Officer)

1. Find your IP address:
   ```bash
   # Windows
   ipconfig
   
   # Linux/Mac
   ifconfig
   ```

2. Run server:
   ```bash
   cd tes-min/server
   node server.js
   ```
   Server binds to `0.0.0.0:3000` (accessible on LAN)

### Client Computer (Police)

1. Create `.env` file:
   ```bash
   cd tes-min/client
   copy example.env .env
   ```

2. Edit `.env` with server's IP:
   ```
   SERVER_URL=http://192.168.1.100:3000
   CLIENT_PORT=3001
   ```

3. Run client:
   ```bash
   node client.js
   ```

4. Open browser: `http://localhost:3001`

---

## Project Structure

```
tes-min/
├── server/
│   ├── package.json
│   ├── server.js           # Main HTTP server
│   ├── example.env         # Example environment variables
│   ├── db/
│   │   ├── init.sql        # Database schema
│   │   └── tes.db          # SQLite database (auto-generated)
│   ├── scripts/
│   │   └── createUser.js   # CLI to create users
│   └── public/
│       ├── login.html
│       ├── officer.html
│       └── style.css
├── client/
│   ├── package.json
│   ├── client.js           # Police client server
│   ├── example.env         # Example environment variables
│   ├── police.html
│   └── keys/               # Auto-generated on first run
│       ├── police_private.pem
│       └── police_public.pem
├── .gitignore
└── README.md
```

---

## Environment Variables

Both server and client automatically load from a `.env` file if present.

### Server Variables (`server/.env`)

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_DES_KEY` | 16-char hex for at-rest encryption | `a1b2c3d4e5f67890` |
| `PORT` | Server port | `3000` |
| `HOST` | Server bind address | `0.0.0.0` |

### Client Variables (`client/.env`)

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_URL` | URL to officer server | `http://localhost:3000` |
| `CLIENT_PORT` | Client UI port | `3001` |

---

## Security Implementation

1. **Password Storage**: scrypt with random salt
2. **Session Key Exchange**: Client generates DES key, encrypts with server RSA public key
3. **Message Encryption**: DES-CBC with session key
4. **Digital Signature**: RSA signature over SHA-256 hash of plaintext
5. **At-Rest Encryption**: Violations stored DES-encrypted with DB_DES_KEY
6. **RSA Key Rotation**: Server rotates RSA keypair every 5 minutes

---

## API Endpoints

### Public
- `GET /api/rsa/current` - Get current RSA public key
- `POST /api/rsa/rotate` - Manually rotate RSA key (testing)

### Auth
- `POST /api/login` - Login with username/password
- `POST /api/logout` - Logout

### Police (authenticated)
- `POST /api/session/exchange` - Exchange DES session key
- `POST /api/violation` - Submit encrypted violation

### Officer (authenticated)
- `GET /api/drivers` - List all drivers
- `POST /api/drivers` - Register new driver
- `GET /api/violations` - List all violations
- `POST /api/violations/decrypt` - Decrypt a violation record

---

## Dependencies

- `node-forge`: DES and RSA cryptographic operations
- `sqlite3`: Database storage (server only)
- Node.js built-ins: `http`, `url`, `crypto`, `fs`, `path`
