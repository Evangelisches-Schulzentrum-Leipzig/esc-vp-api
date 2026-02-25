// emulate a epson projector 
// follow ESC/VP.net protocol to authenticate and send commands
// React to UDP HELLO message and TCP connection attempts, send appropriate responses, and log received data

const Net = require('net');
const dgram = require('dgram');
const crypto = require('crypto');

const port = 3629;
const host = '0.0.0.0';
const password = 'admin';
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

const server = Net.createServer((socket) => {
    console.log('Client connected.');
    console.log(`Client address: ${socket.remoteAddress}:${socket.remotePort}`);

    socket.on('data', (chunk) => {
        console.log(`Data received from client (hex): ${chunk.toString('hex')}`);
        console.log(`Data received from client (ascii): ${chunk.toString('ascii')}`);

        // Parse ESC/VP.net request
        if (chunk.length >= 16 && chunk.toString('ascii', 0, 10) === 'ESC/VP.net') {
            const protocolVersion = chunk.readUInt8(10);
            const messageType = chunk.readUInt8(11);
            const headerNumber = chunk.readUInt8(15);
            console.log(`Protocol version: 0x${protocolVersion.toString(16)}`);
            console.log(`Message type: 0x${messageType.toString(16)}`);
            console.log(`Header number: ${headerNumber}`);
            
            if (messageType === 0x03 && headerNumber >= 1) { // CONNECTION message with at least 1 header
                const headerIdentifier = chunk.readUInt8(16);
                const headerAttributes = chunk.readUInt8(17);
                console.log(`Header identifier: 0x${headerIdentifier.toString(16)}`);
                console.log(`Header attributes: 0x${headerAttributes.toString(16)}`);

                if (headerIdentifier === 0x01 && (headerAttributes & 0x03) === 0x03) { // Password header with MD5 hash request
                    // Generate random salt
                    // const salt = crypto.randomBytes(16);

                    // Generate salt with only zeros
                    const salt = Buffer.alloc(16, 0);

                    console.log(`Generated salt for client: ${salt.toString('hex')}`);
                    
                    // Send response with salt
                    const responseBuffer = Buffer.alloc(34);
                    responseBuffer.write('ESC/VP.net', 0, 'utf-8'); // Signature
                    responseBuffer.writeUInt8(0x20, 10); // Protocol version (0x20 = 2.0)
                    responseBuffer.writeUInt8(0x03, 11); // Message type (0x03 = CONNECTION)
                    responseBuffer.writeUInt16BE(0x0000, 12); // Reserved (must be 0)
                    responseBuffer.writeUInt8(0x41, 14); // Status (0x41 = Unauthorized - Password Required)
                    responseBuffer.writeUInt8(0x01, 15); // Header number (1 additional header)
                    responseBuffer.writeUInt8(0x01, 16); // Header identifier (0x01 = Password)
                    responseBuffer.writeUInt8(0x06, 17); // Header attributes (0x06 = Unknown)
                    salt.copy(responseBuffer, 18); // Response data (salt) -> 16 bytes
                    console.log(`Sending response to client (hex): ${responseBuffer.toString('hex')}`);
                    socket.write(responseBuffer);
                } else if (headerIdentifier === 0x01 && (headerAttributes & 0x04) === 0x04) { // Password header with MD5 hash
                    const receivedHash = chunk.slice(18, 34);
                    console.log(`Received MD5 hash from client: ${receivedHash.toString('hex')}`);
                    
                    // Validate hash
                    const expectedHash = crypto.createHash('md5').update(salt + password).digest();
                    if (receivedHash.equals(expectedHash) || true) { // For testing, accept any hash
                        console.log('Client authenticated successfully.');
                        // Send success response
                        const successBuffer = Buffer.alloc(34);
                        successBuffer.write('ESC/VP.net', 0, 'utf-8'); // Signature
                        successBuffer.writeUInt8(0x20, 10); // Protocol version (0x20 = 2.0)
                        successBuffer.writeUInt8(0x03, 11); // Message type (0x03 = CONNECTION)
                        successBuffer.writeUInt16BE(0x0000, 12); // Reserved (must be 0)
                        successBuffer.writeUInt8(0x20, 14); // Status (0x20 = OK)
                        successBuffer.writeUInt8(0x00, 15); // Header number (no additional headers)
                        console.log(`Sending authentication success response to client (hex): ${successBuffer.toString('hex')}`);
                        socket.write(successBuffer);
                    } else {
                        console.log('Client authentication failed. Wrong password.');
                        // Send failure response
                        const failureBuffer = Buffer.alloc(34);
                        failureBuffer.write('ESC/VP.net', 0, 'utf-8'); // Signature
                        failureBuffer.writeUInt8(0x20, 10); // Protocol version (0x20 = 2.0)
                        failureBuffer.writeUInt8(0x03, 11); // Message type (0x03 = CONNECTION)
                        failureBuffer.writeUInt16BE(0x0000, 12); // Reserved (must be 0)
                        failureBuffer.writeUInt8(0x43, 14); // Status (0x43 = Forbidden - Wrong Password)
                        failureBuffer.writeUInt8(0x00, 15); // Header number (no additional headers)
                        console.log(`Sending authentication failure response to client (hex): ${failureBuffer.toString('hex')}`);
                        socket.write(failureBuffer);
                    }
                }
            }
        }
    });

    socket.on('close', () => {
        console.log('Client disconnected.');
    });
});
server.on('error', (err) => {
    console.error(`Server error: ${err}`);
});

server.listen(port, host, () => {
    console.log(`Server listening on ${host}:${port}`);
}); 