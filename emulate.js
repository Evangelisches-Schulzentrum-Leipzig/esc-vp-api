// emulate a epson projector 
// follow ESC/VP.net protocol to authenticate and send commands

const Net = require('net');
const crypto = require('crypto');

const port = 3629;
const host = '0.0.0.0';
const password = 'admin';

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