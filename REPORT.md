# Traffic Enforcement System (TES)

## Term Project Report

---

## 1. Cover Page

**University:** [Your University Name]

**Department:** Computer Engineering / Computer Science

**Course:** CMSE-456 / CMPE-455 - Computer and Network Security

**Semester:** Fall/Spring

**Year:** 2024-2025

**City, Country:** [Your City], [Your Country]

**Term Project Subject:** Traffic Enforcement System (TES)

**Team Members:**
- [Student Name 1] - [Student ID]
- [Student Name 2] - [Student ID]

**Lecturer:** [Lecturer Name]

**Lab Assistants:** [Assistant Names]

---

## 2. Outline

1. Cover Page
2. Outline
3. Problem Definition
4. TES Detailed Description
5. Description of Tools and Security Methods
6. Description of TES Implementation
   - 6.1 System Architecture
   - 6.2 Database Structure
   - 6.3 Implementation of Actors
   - 6.4 Data Structures for Secure Implementation
   - 6.5 Algorithms for Secure Implementation
   - 6.6 Description of Codes Developed
7. Tests Conducted and Results
8. Installation and Usage Instructions
9. Conclusion
10. References
11. Appendices

---

## 3. Problem Definition

The goal of this project is to develop an online Traffic Enforcement System (TES) that runs on at least two separate computers. The system enables secure communication between traffic police officers in the field and traffic officers at a central station.

The system must meet the following requirements:

1. **Two Actors:** The system has two types of users. Traffic police are the field officers who detect speeding violations. Traffic officers are the station personnel who manage driver records and process violations.

2. **Secure Authentication:** Both actors must authenticate using username and password. Passwords must be stored securely on the server using proper hashing techniques.

3. **Encrypted Communication:** When traffic police detect a speeding violation (speed of 50 km/h or higher), they send a message containing the speed and car plate number. This message must be encrypted using DES and digitally signed using RSA with a hash function.

4. **Penalty Computation:** The traffic officer receives the message, decrypts it, verifies the signature, and computes penalty points according to the following rules:
   - Speed between 50 and 69 km/h: 10 penalty points
   - Speed between 70 and 99 km/h: 20 penalty points
   - Speed of 100 km/h or higher: 50 penalty points

5. **Secure Storage:** Violation records are stored in the database as DES-encrypted messages.

6. **Driver Management:** The traffic officer can register drivers. The system must support at least 3 driver records.

7. **Key Exchange:** Session keys are exchanged using RSA encryption.

8. **Key Rotation:** RSA keys must be periodically updated for security.

---

## 4. TES Detailed Description

The Traffic Enforcement System is a client-server application designed to handle traffic violations securely over a network. The system consists of two main components that run on separate computers.

### Server Component (Traffic Officer Station)

The server is the central hub of the system. It runs on the traffic officer's computer and handles the following responsibilities:

- User authentication for both traffic police and traffic officers
- RSA key generation and periodic rotation
- Session key exchange with clients
- Receiving and decrypting violation reports from traffic police
- Verifying digital signatures on incoming messages
- Computing penalty points based on speed
- Storing violation records with encryption
- Managing driver registration and records
- Providing a web-based dashboard for the traffic officer

### Client Component (Traffic Police Field Unit)

The client runs on the traffic police officer's computer or device. It handles:

- User authentication with the server
- Fetching the current RSA public key from the server
- Generating and exchanging DES session keys
- Creating violation reports with plate number and speed
- Encrypting messages using DES
- Signing messages using RSA digital signatures
- Sending encrypted and signed messages to the server

### Communication Flow

When a traffic police officer detects a speeding violation, the following sequence occurs:

1. The police officer logs into the client application
2. The client fetches the server's current RSA public key
3. The client generates a random DES session key
4. The client encrypts the session key with the server's RSA public key and sends it
5. The server decrypts and stores the session key for that client
6. When reporting a violation, the client creates a JSON message with plate and speed
7. The client signs the message using its RSA private key
8. The client encrypts the message using DES with the session key
9. The server receives the encrypted and signed message
10. The server decrypts the message using the session key
11. The server verifies the signature using the police officer's public key
12. The server checks if the driver is registered
13. The server computes penalty points and stores the encrypted record

---

## 5. Description of Tools and Security Methods

### Programming Tools

**Node.js (JavaScript Runtime)**
We chose Node.js as the runtime environment because it provides excellent support for network programming with its built-in HTTP module. It also has a good ecosystem for cryptographic libraries. Node.js allows us to write both server and client code in JavaScript, which simplified development.

**node-forge Library**
This library provides pure JavaScript implementations of cryptographic algorithms. We used it for:
- DES-CBC encryption and decryption
- RSA key generation
- RSA encryption with OAEP padding
- RSA digital signatures
- SHA-256 hashing for signatures

**sqlite3 Library**
We used SQLite for the database because it is lightweight and does not require a separate database server. This makes the system easier to deploy and test. The sqlite3 library provides a simple API for database operations.

### Security Methods

**Password Hashing**
User passwords are hashed using the scrypt algorithm, which is built into Node.js. Scrypt is a memory-hard function that makes brute force attacks expensive. Each password is hashed with a unique random salt to prevent rainbow table attacks.

**DES Encryption**
DES (Data Encryption Standard) in CBC (Cipher Block Chaining) mode is used for encrypting messages. While DES is considered weak by modern standards due to its 56-bit key size, it was specified in the project requirements. In a production system, we would use AES instead.

**RSA Encryption**
RSA with 2048-bit keys is used for two purposes:
1. Encrypting the DES session key during key exchange (using OAEP padding)
2. Creating digital signatures on messages

**Digital Signatures**
Messages are signed using the following process:
1. Compute SHA-256 hash of the plaintext message
2. Sign the hash using the sender's RSA private key
3. Attach the signature to the encrypted message

The receiver verifies the signature by:
1. Decrypting the message
2. Computing SHA-256 hash of the plaintext
3. Verifying the signature using the sender's public key

**Session Key Exchange**
The session key exchange follows this protocol:
1. Client requests server's current RSA public key
2. Client generates random 8-byte DES key and 8-byte IV
3. Client encrypts the DES key using server's RSA public key with OAEP
4. Client sends encrypted key to server
5. Server decrypts using its RSA private key
6. Both parties now share the same DES session key

**Key Rotation**
The server generates a new RSA key pair every 5 minutes. When keys rotate:
1. All existing client sessions are invalidated
2. Clients must perform key exchange again
3. This limits the impact if a key is compromised

### Communication Tools

**HTTP Protocol**
We used Node.js built-in HTTP module for all client-server communication. The server exposes REST-style API endpoints for various operations. JSON is used as the data format for all API requests and responses.

**Cookie-based Sessions**
User sessions are managed using HTTP cookies. When a user logs in successfully, the server generates a random session ID and sends it as a cookie. The cookie is marked as HttpOnly to prevent JavaScript access.

### Database Management

**SQLite**
SQLite is an embedded SQL database that stores data in a single file. It requires no configuration and works well for applications with moderate data volumes. The database file is created automatically when the server starts.

---

## 6. Description of TES Implementation

### 6.1 System Architecture

The system follows a client-server architecture with the following components:

```
+------------------+          Network          +------------------+
|  Traffic Police  |  <--------------------->  |  Traffic Officer |
|     (Client)     |         HTTP/JSON         |     (Server)     |
+------------------+                           +------------------+
        |                                              |
        v                                              v
+------------------+                           +------------------+
|   Police RSA     |                           |   Server RSA     |
|   Key Pair       |                           |   Key Pair       |
+------------------+                           +------------------+
                                                       |
                                                       v
                                               +------------------+
                                               |    SQLite DB     |
                                               |   (tes.db)       |
                                               +------------------+
```

**Server Machine:**
- Runs the main HTTP server on port 3000
- Hosts the officer dashboard web interface
- Manages the SQLite database
- Handles RSA key generation and rotation
- Processes incoming violation reports

**Client Machine:**
- Runs a lightweight HTTP server on port 3001
- Hosts the police UI web interface
- Manages local RSA key pair for signing
- Handles session key exchange
- Sends encrypted violation reports

Both machines must be connected to the same network. The client needs to know the server's IP address to connect.

### 6.2 Database Structure

The SQLite database contains three tables:

**users Table**
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    pass_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('officer', 'police'))
);
```
This table stores user accounts. The password is stored as a scrypt hash with a random salt. The role field determines what the user can access.

**drivers Table**
```sql
CREATE TABLE drivers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plate TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL
);
```
This table stores registered drivers. The plate number must be unique. Only traffic officers can add drivers.

**violations Table**
```sql
CREATE TABLE violations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plate TEXT NOT NULL,
    speed INTEGER NOT NULL,
    points INTEGER NOT NULL,
    stored_ciphertext_b64 TEXT NOT NULL,
    iv_b64 TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);
```
This table stores violation records. The actual violation data is stored encrypted in the stored_ciphertext_b64 field. The iv_b64 field contains the initialization vector needed for decryption. The plate, speed, and points fields are stored in plain text for querying purposes, while the encrypted field contains the complete record for secure storage.

### 6.3 Implementation of Actors

**Traffic Officer Implementation**

The traffic officer interacts with the system through a web browser. After logging in at the server URL, they see a dashboard with the following features:

1. **Driver Registration Form:** A simple form to add new drivers by entering their license plate and name. The plate number is automatically converted to uppercase.

2. **Registered Drivers List:** Shows all drivers as cards, with each driver's violations listed underneath. Drivers with no violations show "No violations recorded". The total penalty points for each driver are displayed.

3. **Violation Decryption:** Each violation record has a "Decrypt" button that reveals the encrypted data stored in the database.

4. **Logout Button:** Ends the session and returns to the login page.

**Traffic Police Implementation**

The traffic police officer uses the client application, which provides a simple web interface:

1. **Login Form:** Enter username and password to authenticate with the server. Upon successful login, the client automatically performs RSA key exchange.

2. **Connection Status:** Shows whether the client is connected and displays the current server RSA key ID.

3. **Violation Report Form:** Enter the license plate number and speed. Clicking submit will encrypt and sign the message, then send it to the server.

4. **Validation:** If the speed is below 50 km/h, the system shows an error and does not send the message. If the plate is not registered, the server rejects the report.

5. **Logout Button:** Clears the session and requires re-login.

### 6.4 Data Structures for Secure Implementation

**RSA Key Storage (Server)**
```javascript
let currentRSA = {
    keyId: "timestamp-version",      // Unique identifier
    privateKey: forge.pki.rsa.PrivateKey,
    publicKey: forge.pki.rsa.PublicKey,
    publicKeyPem: "-----BEGIN PUBLIC KEY-----...",
    createdAt: 1234567890
};
```
The server maintains the current RSA key pair in memory. The keyId is a combination of timestamp and version number for tracking.

**RSA Key Storage (Client)**
```javascript
let policePrivateKey = forge.pki.rsa.PrivateKey;
let policePublicKey = forge.pki.rsa.PublicKey;
let policePublicKeyPem = "-----BEGIN PUBLIC KEY-----...";
```
The client generates an RSA key pair on first run and stores it in PEM files for persistence.

**Session Storage (Server)**
```javascript
const sessions = new Map();  // sessionId -> { username, role }
const clientSessions = new Map();  // sessionId -> { desKey, iv }
```
Two maps track active sessions. The first maps session IDs to user information. The second maps session IDs to DES session keys for message decryption.

**Violation Message Structure**
```javascript
// Plaintext (before encryption)
{
    plate: "ABC123",
    speed: 85,
    ts: "2024-12-27T10:30:00.000Z"
}

// Transmitted payload
{
    iv_b64: "base64 encoded IV",
    ciphertext_b64: "base64 encoded DES ciphertext",
    signature_b64: "base64 encoded RSA signature",
    police_public_key_pem: "-----BEGIN PUBLIC KEY-----..."
}
```

### 6.5 Algorithms for Secure Implementation

**Password Hashing Algorithm**
```
Input: password (string)
Output: hash (hex string), salt (hex string)

1. Generate 16 random bytes as salt
2. Derive 64-byte key using scrypt(password, salt)
3. Convert derived key to hex string
4. Store both hash and salt in database
```

**Login Verification Algorithm**
```
Input: username, password
Output: success/failure, session cookie

1. Fetch user record by username
2. If not found, return failure
3. Compute hash using scrypt(password, stored_salt)
4. Compare with stored_hash
5. If match, generate random session ID
6. Store session in memory map
7. Return success with session cookie
```

**RSA Key Exchange Algorithm**
```
Client side:
1. Fetch server RSA public key via GET /api/rsa/current
2. Generate 8 random bytes as DES key
3. Generate 8 random bytes as IV
4. Encrypt DES key using RSA-OAEP with server public key
5. Send encrypted key and IV to POST /api/session/exchange

Server side:
1. Receive encrypted session key
2. Verify key_id matches current RSA key
3. Decrypt using current RSA private key
4. Store DES key in clientSessions map
5. Return success
```

**Message Signing Algorithm**
```
Input: plaintext message, private key
Output: base64 signature

1. Create SHA-256 hash of plaintext
2. Sign hash bytes using RSA private key
3. Encode signature as base64
```

**Message Encryption Algorithm**
```
Input: plaintext, DES key (hex), IV (hex)
Output: base64 ciphertext

1. Convert key from hex to bytes (8 bytes)
2. Convert IV from hex to bytes (8 bytes)
3. Create DES-CBC cipher with key and IV
4. Encrypt plaintext as UTF-8 bytes
5. Encode ciphertext as base64
```

**Violation Processing Algorithm**
```
Input: encrypted payload from client
Output: stored violation record

1. Get client session key from memory
2. DES decrypt ciphertext using session key
3. Parse plaintext as JSON
4. Extract police public key from payload
5. Verify RSA signature over plaintext
6. If invalid signature, reject
7. Check if plate exists in drivers table
8. If not registered, reject
9. Compute penalty points based on speed
10. Generate random IV for storage
11. Encrypt record using DB_DES_KEY
12. Insert into violations table
```

**Penalty Points Computation**
```
Input: speed (integer)
Output: points (integer)

if speed >= 100:
    return 50
else if speed >= 70:
    return 20
else if speed >= 50:
    return 10
else:
    return 0  // Should not happen, filtered earlier
```

### 6.6 Description of Codes Developed

The project consists of the following main code files:

**server/server.js (Appendix 1)**
This is the main server file containing approximately 450 lines of code. It includes:
- Environment loading from .env file
- HTTP server setup using Node.js http module
- RSA key generation and rotation logic
- All API endpoint handlers
- Database operations
- DES encryption and decryption functions
- Password hashing and verification

**server/scripts/createUser.js (Appendix 2)**
A command-line utility for creating user accounts. It:
- Parses command line arguments
- Initializes the database if needed
- Hashes the password with a random salt
- Inserts the user into the database

**server/public/login.html (Appendix 3)**
The login page HTML with embedded JavaScript. Contains a form for username and password entry, and handles the login API call.

**server/public/officer.html (Appendix 4)**
The officer dashboard HTML with embedded JavaScript. Features:
- Driver registration form
- Dynamic driver list with violations
- Decrypt functionality for viewing stored records
- Refresh and logout buttons

**server/public/style.css (Appendix 5)**
CSS styles for the server web pages. Uses a dark theme with blue and red accent colors.

**client/client.js (Appendix 6)**
The main client file containing approximately 280 lines of code. It includes:
- Environment loading from .env file
- RSA key pair generation and storage
- HTTP server for the police UI
- API proxy to the main server
- DES encryption for outgoing messages
- RSA signing for message authentication

**client/police.html (Appendix 7)**
The police interface HTML with embedded JavaScript. Contains:
- Login form with key exchange
- Violation report form
- Connection status display
- Logout button

---

## 7. Tests Conducted and Results

We conducted several tests to verify the system works correctly.

### Test 1: User Creation

**Purpose:** Verify users can be created with proper password hashing.

**Steps:**
1. Run createUser.js with officer role
2. Run createUser.js with police role
3. Verify users exist in database

**Command:**
```bash
node scripts/createUser.js --role officer --username testoff --password test123
node scripts/createUser.js --role police --username testpol --password test456
```

**Result:** Users were created successfully. Database shows hashed passwords with unique salts.

### Test 2: Login Authentication

**Purpose:** Verify login works with correct credentials and fails with incorrect ones.

**Steps:**
1. Try logging in with correct credentials
2. Try logging in with wrong password
3. Try logging in with non-existent user

**Result:** Correct credentials allowed access. Wrong password showed "Invalid credentials". Non-existent user also showed "Invalid credentials" (no information leak about valid usernames).

### Test 3: RSA Key Exchange

**Purpose:** Verify session key exchange works correctly.

**Steps:**
1. Login as police user
2. Check server logs for key exchange message
3. Verify client shows "Connected" status

**Result:** Client successfully fetched RSA public key, encrypted DES session key, and sent it to server. Server logs showed "Key exchange complete for testpol".

### Test 4: RSA Key Rotation

**Purpose:** Verify keys rotate automatically and manually.

**Steps:**
1. Note current key ID
2. Call POST /api/rsa/rotate
3. Verify key ID changed
4. Wait 5 minutes
5. Verify key ID changed again

**Result:** Manual rotation worked immediately. Automatic rotation triggered after 5 minutes. Server logs showed rotation messages.

### Test 5: Driver Registration

**Purpose:** Verify drivers can be registered by officer.

**Steps:**
1. Login as officer
2. Add driver with plate "ABC123" and name "John Smith"
3. Add two more drivers
4. Verify all three appear in list

**Result:** All drivers registered successfully. Duplicate plates were rejected with error message.

### Test 6: Violation Submission (Speed >= 50)

**Purpose:** Verify violations are encrypted, signed, and stored.

**Steps:**
1. Login as police
2. Enter registered plate "ABC123" with speed 75
3. Submit violation
4. Check officer dashboard

**Result:** Violation was sent successfully. Server decrypted message, verified signature, computed 20 penalty points, and stored encrypted record.

### Test 7: Violation Rejection (Speed < 50)

**Purpose:** Verify low speeds are not sent.

**Steps:**
1. Enter plate with speed 45
2. Try to submit

**Result:** Client showed error "Speed below 50 km/h - Violation not sent". No network request was made.

### Test 8: Violation Rejection (Unregistered Plate)

**Purpose:** Verify unregistered plates are rejected.

**Steps:**
1. Enter unregistered plate "XYZ999" with speed 80
2. Submit violation

**Result:** Server returned error "Driver with plate XYZ999 is not registered".

### Test 9: Penalty Points Calculation

**Purpose:** Verify correct points for different speeds.

**Steps:**
1. Submit violations with speeds 55, 75, and 105
2. Check computed points

**Results:**
- Speed 55: 10 points (correct)
- Speed 75: 20 points (correct)
- Speed 105: 50 points (correct)

### Test 10: At-Rest Decryption

**Purpose:** Verify stored violations can be decrypted by officer.

**Steps:**
1. Login as officer
2. Find a violation record
3. Click "Decrypt" button

**Result:** Decrypted record showed original plate, speed, points, and timestamp in JSON format.

### Test 11: Two-Computer Communication

**Purpose:** Verify system works across network.

**Steps:**
1. Run server on Computer A (IP: 192.168.1.100)
2. Configure client on Computer B with SERVER_URL
3. Login from Computer B
4. Submit violation from Computer B
5. Check Computer A dashboard

**Result:** Communication worked correctly over LAN. Encryption and signatures verified properly.

---

## 8. Installation and Usage Instructions

### Prerequisites

- Node.js version 14 or higher
- Two computers connected to the same network (for full testing)

### Server Installation (Traffic Officer Computer)

1. Extract or clone the project files

2. Open terminal and navigate to server folder:
   ```bash
   cd tes-min/server
   ```

3. Install dependencies:
   ```bash
   npm install
   ```

4. (Optional) Create environment file:
   ```bash
   copy example.env .env
   ```

5. Create user accounts:
   ```bash
   node scripts/createUser.js --role officer --username officer1 --password officer123
   node scripts/createUser.js --role police --username police1 --password police123
   ```

6. Start the server:
   ```bash
   node server.js
   ```

7. Server will display:
   ```
   ========================================
   [TES Server] Running on http://0.0.0.0:3000
   [TES Server] Current RSA Key ID: xxxxx-v1
   [TES Server] RSA rotation interval: 300s (5 min)
   ========================================
   ```

### Client Installation (Traffic Police Computer)

1. Copy client folder to police computer

2. Open terminal and navigate to client folder:
   ```bash
   cd tes-min/client
   ```

3. Install dependencies:
   ```bash
   npm install
   ```

4. Create environment file:
   ```bash
   copy example.env .env
   ```

5. Edit .env and set server IP:
   ```
   SERVER_URL=http://192.168.1.100:3000
   CLIENT_PORT=3001
   ```

6. Start the client:
   ```bash
   node client.js
   ```

### Usage Instructions

**Traffic Officer:**
1. Open browser to http://localhost:3000
2. Login with officer credentials
3. Register at least 3 drivers using the form
4. Violations will appear under each driver automatically
5. Click "Decrypt" to view stored encrypted data
6. Click "Refresh" to update the list
7. Click "Logout" when finished

**Traffic Police:**
1. Open browser to http://localhost:3001
2. Login with police credentials
3. Wait for "Connected" status
4. Enter license plate of registered driver
5. Enter speed (must be 50 or higher)
6. Click "Send Encrypted Violation"
7. Check result message
8. Click "Logout" when finished

---

## 9. Conclusion

We successfully developed a Traffic Enforcement System that meets all the project requirements. The system provides secure communication between traffic police and traffic officers using industry-standard cryptographic techniques.

Key achievements:
- Implemented secure password storage using scrypt hashing
- Implemented DES encryption for message confidentiality
- Implemented RSA digital signatures for message authentication
- Implemented RSA-based session key exchange
- Implemented periodic RSA key rotation
- Created a functional two-computer distributed system
- Stored violation records with at-rest encryption

Lessons learned:
- Understanding the importance of proper key management
- Learning how session key exchange protocols work
- Experiencing the complexity of implementing cryptographic systems
- Appreciating why standardized protocols and libraries are important

Potential improvements for future work:
- Replace DES with AES for stronger encryption
- Add HTTPS/TLS for transport layer security
- Implement real-time key rotation notifications
- Add more comprehensive audit logging
- Implement role-based access control with more granularity

The project gave us valuable hands-on experience with cryptographic concepts that we learned in the course.

---

## 10. References

1. Ferguson, N., Schneier, B., & Kohno, T. (2010). Cryptography Engineering: Design Principles and Practical Applications. Wiley.

2. Node.js Documentation. (2024). Crypto Module. https://nodejs.org/api/crypto.html

3. node-forge Library Documentation. (2024). https://github.com/digitalbazaar/forge

4. SQLite Documentation. (2024). https://www.sqlite.org/docs.html

5. NIST Special Publication 800-132. (2010). Recommendation for Password-Based Key Derivation.

6. RFC 8017. (2016). PKCS #1: RSA Cryptography Specifications Version 2.2.

7. NIST FIPS 46-3. (1999). Data Encryption Standard (DES).

---

## 11. Appendices

### Appendix 1: Server Source Code (server/server.js)

See attached file: `server/server.js`

This file contains the main server implementation including:
- Lines 1-8: Module imports
- Lines 10-26: Environment file loading
- Lines 28-33: Configuration constants
- Lines 35-42: Database initialization
- Lines 44-46: In-memory session stores
- Lines 48-80: RSA key management and rotation
- Lines 82-112: Utility functions (parseBody, parseCookies, etc.)
- Lines 114-141: DES encryption/decryption functions
- Lines 143-149: Penalty calculation function
- Lines 151-450: HTTP request handlers for all endpoints

### Appendix 2: User Creation Script (server/scripts/createUser.js)

See attached file: `server/scripts/createUser.js`

This script handles:
- Command line argument parsing
- Database connection and initialization
- Password hashing with scrypt
- User insertion into database

### Appendix 3: Login Page (server/public/login.html)

See attached file: `server/public/login.html`

Contains the login form HTML and JavaScript for handling login submission.

### Appendix 4: Officer Dashboard (server/public/officer.html)

See attached file: `server/public/officer.html`

Contains the officer interface with:
- Driver registration form
- Driver list with violations
- Decrypt functionality
- Logout handling

### Appendix 5: Styles (server/public/style.css)

See attached file: `server/public/style.css`

CSS styles for the web interface using a dark theme.

### Appendix 6: Client Source Code (client/client.js)

See attached file: `client/client.js`

This file contains the client implementation including:
- Lines 1-6: Module imports
- Lines 8-25: Environment file loading
- Lines 27-41: RSA key generation and loading
- Lines 43-48: Client state variables
- Lines 50-88: HTTP request helpers
- Lines 90-99: DES encryption function
- Lines 101-144: RSA key fetching and session exchange
- Lines 146-181: Violation submission with signing
- Lines 183-280: HTTP server for police UI

### Appendix 7: Police Interface (client/police.html)

See attached file: `client/police.html`

Contains the police interface with:
- Login form
- Connection status display
- Violation report form
- Logout handling

### Appendix 8: Database Schema (server/db/init.sql)

See attached file: `server/db/init.sql`

Contains SQL statements for creating the users, drivers, and violations tables.

---

*End of Report*

