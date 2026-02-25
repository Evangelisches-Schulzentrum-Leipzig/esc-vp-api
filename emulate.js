// emulate a epson projector 
// follow ESC/VP.net protocol to authenticate and send commands
// React to UDP HELLO message and TCP connection attempts, send appropriate responses, and log received data

const Net = require('net');
const dgram = require('dgram');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Load .env file without external packages
const envPath = path.resolve(__dirname, '.env');
if (fs.existsSync(envPath)) {
    fs.readFileSync(envPath, 'utf-8')
        .split('\n')
        .filter(line => line.trim() && !line.startsWith('#'))
        .forEach(line => {
            const idx = line.indexOf('=');
            if (idx !== -1) {
                const key = line.slice(0, idx).trim();
                const value = line.slice(idx + 1).trim().replace(/^["']|["']$/g, '');
                if (!process.env[key]) process.env[key] = value;
            }
        });
}

const port = 3629;
const host = '0.0.0.0';
const password = 'admin';
const fakeSalt = Buffer.from(process.env.FAKE_SALT || '00000000000000000000000000000000', 'hex');
const projectorName = 'EPSON Projector';

// ==================== UDP HELLO Server (Session-less Mode) ====================
const udpServer = dgram.createSocket('udp4');

udpServer.on('message', (msg, rinfo) => {
    console.log(`\n[UDP] Received ${msg.length} bytes from ${rinfo.address}:${rinfo.port}`);
    console.log(`[UDP] Data (hex): ${msg.toString('hex')}`);
    console.log(`[UDP] Data (ascii): ${msg.toString('ascii')}`);

    // Validate minimum packet size
    if (msg.length < 16) {
        console.log('[UDP] Packet too short, ignoring.');
        return;
    }

    // Check protocol identifier
    if (msg.toString('ascii', 0, 10) !== 'ESC/VP.net') {
        console.log('[UDP] Invalid protocol identifier, sending Bad Request.');
        const errBuf = buildResponse(0x01, 0x40, []);
        udpServer.send(errBuf, rinfo.port, rinfo.address);
        return;
    }

    const protocolVersion = msg.readUInt8(10);
    const messageType = msg.readUInt8(11);
    const reserved = msg.readUInt16BE(12);
    const statusByte = msg.readUInt8(14);
    const headerCount = msg.readUInt8(15);

    console.log(`[UDP] Version: 0x${protocolVersion.toString(16)}, Type: ${messageType}, Status: 0x${statusByte.toString(16)}, Headers: ${headerCount}`);

    // Validate version
    if (protocolVersion !== 0x10) {
        console.log('[UDP] Unsupported protocol version, sending Version Not Supported.');
        const errBuf = buildResponse(0x01, 0x55, []);
        udpServer.send(errBuf, rinfo.port, rinfo.address);
        return;
    }

    // Validate reserved field and status byte
    if (reserved !== 0 || statusByte !== 0x00) {
        console.log('[UDP] Invalid reserved field or status byte, sending Bad Request.');
        const errBuf = buildResponse(0x01, 0x40, []);
        udpServer.send(errBuf, rinfo.port, rinfo.address);
        return;
    }

    // In UDP session-less mode, only HELLO (type 1) is allowed
    if (messageType !== 0x01) {
        console.log(`[UDP] Type ${messageType} not allowed in session-less mode, sending Request Not Allowed.`);
        const errBuf = buildResponse(messageType, 0x45, []);
        udpServer.send(errBuf, rinfo.port, rinfo.address);
        return;
    }

    // HELLO request must have 0 headers
    if (headerCount !== 0) {
        console.log('[UDP] HELLO request must have 0 headers, sending Bad Request.');
        const errBuf = buildResponse(0x01, 0x40, []);
        udpServer.send(errBuf, rinfo.port, rinfo.address);
        return;
    }

    console.log('[UDP] Valid HELLO request received. Sending HELLO response with projector info.');

    // Build response headers
    const headers = [];

    // Header: Projector-Name (identifier 3, attribute 1 = US-ASCII)
    const nameHeader = Buffer.alloc(18);
    nameHeader.writeUInt8(0x03, 0); // Header identifier: Projector-Name
    nameHeader.writeUInt8(0x01, 1); // Header attribute: US-ASCII
    nameHeader.write(projectorName.substring(0, 16).padEnd(16, '\0'), 2, 'ascii');
    headers.push(nameHeader);

    // Header: IM-Type (identifier 4, attribute 0x41 = Type I)
    const imTypeHeader = Buffer.alloc(18);
    imTypeHeader.writeUInt8(0x04, 0); // Header identifier: IM-Type
    imTypeHeader.writeUInt8(0x41, 1); // Header attribute: Type I
    imTypeHeader.fill(0x00, 2);       // Information: all zeros
    headers.push(imTypeHeader);

    // Header: Projector-Command-Type (identifier 5, attribute 0x21 = ESC/VP21 Ver1.0)
    const cmdTypeHeader = Buffer.alloc(18);
    cmdTypeHeader.writeUInt8(0x05, 0); // Header identifier: Projector-Command-Type
    cmdTypeHeader.writeUInt8(0x21, 1); // Header attribute: ESC/VP21 Ver1.0
    cmdTypeHeader.fill(0x00, 2);       // Information: all zeros
    headers.push(cmdTypeHeader);

    const responseBuf = buildResponse(0x01, 0x20, headers);
    console.log(`[UDP] Sending HELLO response (hex): ${responseBuf.toString('hex')}`);
    udpServer.send(responseBuf, rinfo.port, rinfo.address);
});

udpServer.on('error', (err) => {
    console.error(`[UDP] Server error: ${err}`);
    udpServer.close();
});

udpServer.bind(port, host, () => {
    console.log(`[UDP] HELLO server listening on ${host}:${port}`);
});

// ==================== Helper: Build ESC/VP.net response ====================
function buildResponse(type, status, headers) {
    const headerCount = headers.length;
    const buf = Buffer.alloc(16 + headerCount * 18);
    buf.write('ESC/VP.net', 0, 'ascii');  // Protocol identifier
    buf.writeUInt8(0x10, 10);             // Version (1.0)
    buf.writeUInt8(type, 11);             // Type identifier
    buf.writeUInt16BE(0x0000, 12);        // Reserved
    buf.writeUInt8(status, 14);           // Status code
    buf.writeUInt8(headerCount, 15);      // Number of headers
    for (let i = 0; i < headerCount; i++) {
        headers[i].copy(buf, 16 + i * 18);
    }
    return buf;
}

// ==================== TCP Server (Session Mode) ====================
// Per spec: TCP allows only type 2 (PASSWORD) and type 3 (CONNECT).
// After error responses and PASSWORD responses, the TCP connection is cut.
// After successful CONNECT, the connection stays open for ESC/VP21 commands.

const server = Net.createServer((socket) => {
    console.log(`[TCP] Client connected: ${socket.remoteAddress}:${socket.remotePort}`);

    // Register error handler first to prevent unhandled 'error' events
    socket.on('error', (err) => {
        console.error(`[TCP] Socket error from ${socket.remoteAddress}:${socket.remotePort}: ${err.message}`);
    });

    socket.on('data', (chunk) => {
        console.log(`[TCP] Data received (hex): ${chunk.toString('hex')}`);
        console.log(`[TCP] Data received (ascii): ${chunk.toString('ascii')}`);

        // --- Common validation (spec §6.1) ---

        // Minimum packet size
        if (chunk.length < 16) {
            console.log('[TCP] Packet too short, ignoring.');
            return;
        }

        // Protocol identifier
        if (chunk.toString('ascii', 0, 10) !== 'ESC/VP.net') {
            console.log('[TCP] Invalid protocol identifier, sending Bad Request and disconnecting.');
            socket.end(buildResponse(0x00, 0x40, []));
            return;
        }

        const protocolVersion = chunk.readUInt8(10);
        const messageType = chunk.readUInt8(11);
        const reserved = chunk.readUInt16BE(12);
        const statusByte = chunk.readUInt8(14);
        const headerCount = chunk.readUInt8(15);

        console.log(`[TCP] Version: 0x${protocolVersion.toString(16)}, Type: ${messageType}, Status: 0x${statusByte.toString(16)}, Headers: ${headerCount}`);

        // Version must be 0x10 (spec §6.1)
        if (protocolVersion !== 0x10 && false) {
            console.log('[TCP] Unsupported version, sending Version Not Supported and disconnecting.');
            socket.end(buildResponse(messageType, 0x55, []));
            return;
        }

        // Reserved must be 0, status must be 0x00 for requests (spec §6.1)
        if (reserved !== 0 || statusByte !== 0x00) {
            console.log('[TCP] Invalid reserved/status, sending Bad Request and disconnecting.');
            socket.end(buildResponse(messageType, 0x40, []));
            return;
        }

        // Type must be 0..3 (spec §6.1)
        if (messageType < 0 || messageType > 3) {
            console.log('[TCP] Type out of range, sending Bad Request and disconnecting.');
            socket.end(buildResponse(messageType, 0x40, []));
            return;
        }

        // TCP only allows type 2 (PASSWORD) and type 3 (CONNECT) (spec §6.3)
        if (messageType !== 0x02 && messageType !== 0x03) {
            console.log(`[TCP] Type ${messageType} not allowed in session mode, sending Request Not Allowed and disconnecting.`);
            socket.end(buildResponse(messageType, 0x45, []));
            return;
        }

        // --- Parse headers ---
        const headers = [];
        for (let i = 0; i < headerCount; i++) {
            const offset = 16 + i * 18;
            if (offset + 18 > chunk.length) break;
            headers.push({
                id: chunk.readUInt8(offset),
                attr: chunk.readUInt8(offset + 1),
                info: chunk.slice(offset + 2, offset + 18)
            });
        }

        // --- PASSWORD request (type 2) (spec §5.1) ---
        if (messageType === 0x02) {
            handlePasswordRequest(socket, headerCount, headers);
            return;
        }

        // --- CONNECT request (type 3) (spec §5.2) ---
        if (messageType === 0x03) {
            handleConnectRequest(socket, headerCount, headers);
            return;
        }
    });

    socket.on('close', () => {
        console.log(`[TCP] Client disconnected: ${socket.remoteAddress}:${socket.remotePort}`);
    });
});

// --- PASSWORD handler (spec §5.1) ---
// After response, TCP connection is always cut.
function handlePasswordRequest(socket, headerCount, headers) {
    // Validate: only Password (id 1) and New-Password (id 2) headers allowed (spec §6.5)
    for (const h of headers) {
        if (h.id !== 0x01 && h.id !== 0x02) {
            console.log(`[TCP] PASSWORD request has invalid header id ${h.id}, sending Bad Request.`);
            socket.end(buildResponse(0x02, 0x40, []));
            return;
        }
    }

    if (headerCount === 0) {
        // PASSWORD check: is a password set? (spec §5.1.1)
        if (password) {
            console.log('[TCP] PASSWORD check: password is set, sending Unauthorized.');
            socket.end(buildResponse(0x02, 0x41, []));
        } else {
            console.log('[TCP] PASSWORD check: no password set, sending OK.');
            socket.end(buildResponse(0x02, 0x20, []));
        }
        return;
    }

    // PASSWORD confirm: check the provided password (spec §5.1.2)
    // Collect all password headers by attribute
    const pwHeaders = headers.filter(h => h.id === 0x01);
    if (pwHeaders.length === 0) {
        console.log('[TCP] PASSWORD confirm: no password header, sending Bad Request.');
        socket.end(buildResponse(0x02, 0x40, []));
        return;
    }

    // Find specific header types
    const plainHeader = pwHeaders.find(h => h.attr === 0x01);
    const hashHeader = pwHeaders.find(h => h.attr === 0x04);
    const saltHeader = pwHeaders.find(h => h.attr === 0x05);

    if (plainHeader) {
        // Plain text password
        const receivedPw = plainHeader.info.toString('ascii').replace(/\0/g, '');
        console.log(`[TCP] PASSWORD confirm (plain): received="${receivedPw}"`);
        if (!password || receivedPw === password) {
            console.log('[TCP] PASSWORD confirm: OK.');
            socket.end(buildResponse(0x02, 0x20, []));
        } else {
            console.log('[TCP] PASSWORD confirm: wrong password, sending Forbidden.');
            socket.end(buildResponse(0x02, 0x43, []));
        }
    } else if (hashHeader) {
        // MD5 hash (attr 0x04), optionally accompanied by salt echo (attr 0x05)
        const receivedHash = hashHeader.info;
        console.log(`[TCP] PASSWORD confirm (MD5): hash=${receivedHash.toString('hex')}`);
        if (saltHeader) {
            console.log(`[TCP] PASSWORD confirm (MD5): salt echo=${saltHeader.info.toString('hex')}`);
        }
        // TODO: validate hash = MD5(salt + password) when implementing real auth
        console.log('[TCP] PASSWORD confirm (MD5): accepting hash (emulation mode).');
        socket.end(buildResponse(0x02, 0x20, []));
    } else {
        console.log(`[TCP] PASSWORD confirm: unsupported header attrs [${pwHeaders.map(h => '0x' + h.attr.toString(16)).join(', ')}], sending Bad Request.`);
        socket.end(buildResponse(0x02, 0x40, []));
    }
}

// --- CONNECT handler (spec §5.2) ---
// After error, TCP connection is cut.
// After success, TCP stays open for ESC/VP21 bidirectional session.
function handleConnectRequest(socket, headerCount, headers) {
    if (headerCount === 0) {
        // CONNECT without password (spec §5.2.1)
        if (password) {
            // Password is set but not provided (spec §6.4 CONNECT errors)
            console.log('[TCP] CONNECT without password but password is required, sending Unauthorized and disconnecting.');
            socket.end(buildResponse(0x03, 0x41, []));
        } else {
            console.log('[TCP] CONNECT without password: OK. ESC/VP21 session started.');
            socket.write(buildResponse(0x03, 0x20, []));
            // Connection stays open for ESC/VP21 commands
        }
        return;
    }

    // Validate: only Password (id 1) headers should be used for CONNECT
    const pwHeaders = headers.filter(h => h.id === 0x01);
    if (pwHeaders.length === 0) {
        console.log('[TCP] CONNECT: no password header found, sending Bad Request and disconnecting.');
        socket.end(buildResponse(0x03, 0x40, []));
        return;
    }

    // Find specific header types by attribute
    const plainHeader = pwHeaders.find(h => h.attr === 0x01);
    const challengeHeader = pwHeaders.find(h => h.attr === 0x03);
    const hashHeader = pwHeaders.find(h => h.attr === 0x04);
    const saltEchoHeader = pwHeaders.find(h => h.attr === 0x05);

    if (plainHeader) {
        // Plain text password (spec §5.2.2)
        const receivedPw = plainHeader.info.toString('ascii').replace(/\0/g, '');
        console.log(`[TCP] CONNECT with plain password: received="${receivedPw}"`);
        if (!password || receivedPw === password) {
            console.log('[TCP] CONNECT: authenticated OK. ESC/VP21 session started.');
            socket.write(buildResponse(0x03, 0x20, []));
            // Connection stays open for ESC/VP21 commands
        } else {
            console.log('[TCP] CONNECT: wrong password, sending Forbidden and disconnecting.');
            socket.end(buildResponse(0x03, 0x43, []));
        }
    } else if (challengeHeader) {
        // Client is requesting MD5 challenge — send empty salt (emulation mode)
        const salt = fakeSalt; // Empty salt for emulation
        console.log(`[TCP] CONNECT: MD5 challenge requested, sending salt: ${salt.toString('hex')}`);

        // Build Unauthorized response with salt in a password header
        const saltRespHeader = Buffer.alloc(18);
        saltRespHeader.writeUInt8(0x01, 0);  // Header id: Password
        saltRespHeader.writeUInt8(0x06, 1);  // Header attr: salt delivery
        salt.copy(saltRespHeader, 2);        // 16-byte salt

        socket.write(buildResponse(0x03, 0x41, [saltRespHeader]));
    } else if (hashHeader) {
        // Client sent MD5 hash (attr 0x04), typically accompanied by salt echo (attr 0x05)
        const receivedHash = hashHeader.info;
        console.log(`[TCP] CONNECT: MD5 hash received: ${receivedHash.toString('hex')}`);
        if (saltEchoHeader) {
            console.log(`[TCP] CONNECT: salt echo received: ${saltEchoHeader.info.toString('hex')}`);
            console.log(`[TCP] CONNECT: full hash header: ${receivedHash.toString('hex')}${saltEchoHeader.info.toString('hex')}`);
        }
        // TODO: validate hash = MD5(salt + password) when implementing real auth
        console.log('[TCP] CONNECT: accepting hash (emulation mode). ESC/VP21 session started.');
        socket.write(buildResponse(0x03, 0x20, []));
        // Connection stays open for ESC/VP21 commands
    } else {
        console.log(`[TCP] CONNECT: unsupported password attrs [${pwHeaders.map(h => '0x' + h.attr.toString(16)).join(', ')}], sending Bad Request and disconnecting.`);
        socket.end(buildResponse(0x03, 0x40, []));
    }
}
server.on('error', (err) => {
    console.error(`Server error: ${err}`);
});

process.on('uncaughtException', (err) => {
    console.error(`Uncaught exception: ${err.message}`);
});

server.listen(port, host, () => {
    console.log(`Server listening on ${host}:${port}`);
}); 