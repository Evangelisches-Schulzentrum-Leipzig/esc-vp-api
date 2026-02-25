const Net = require('net');
const crypto = require('crypto');

const port = 3629;
const host = '10.101.10.38';
const password = 'admin';

const helloMsgBuffer = Buffer.alloc(34);
helloMsgBuffer.write('ESC/VP.net', 0, 'utf-8'); // Signature
helloMsgBuffer.writeUInt8(0x20, 10); // Protocol version (0x20 = 2.0)
helloMsgBuffer.writeUInt8(0x03, 11); // Message type (0x03 = CONNECTION)
helloMsgBuffer.writeUInt16BE(0x0000, 12); // Reserved (must be 0)
helloMsgBuffer.writeUInt8(0x00, 14); // Request
helloMsgBuffer.writeUInt8(0x01, 15); // Header number (1 additional header)
helloMsgBuffer.writeUInt8(0x01, 16); // Header identifier (0x01 = Password)
helloMsgBuffer.writeUInt8(0x03, 17); // Header attributes (0x03 = Request MD5 Hash)
helloMsgBuffer.write(''.padEnd(16, '\0'), 18, 'utf-8'); // Request data (empty password)


const client = new Net.Socket();

client.connect({ port: port, host: host }, function() {
    console.log('TCP connection established.');

    console.log(`Sending data: ${helloMsgBuffer.toString('hex')}`);
    client.write(helloMsgBuffer);
});

client.on('data', function(chunk) {
    console.log(`Data received (hex): ${chunk.toString('hex')}`);
    console.log(`Data received (ascii): ${chunk.toString('ascii')}`);

    // Parse ESC/VP.net response
    if (chunk.length >= 16 && chunk.toString('ascii', 0, 10) === 'ESC/VP.net') {
        const status = chunk.readUInt8(14);
        const statusMap = {
            0x20: 'OK',
            0x40: 'Bad Request',
            0x41: 'Unauthorized (Password Required)',
            0x43: 'Forbidden (Wrong Password)',
            0x45: 'Request Not Allowed',
            0x53: 'Service Unavailable (Busy)',
            0x55: 'Version Not Supported'
        };
        console.log(`Response status: ${statusMap[status] || 'Unknown'} (0x${status.toString(16)})`);
        if (status in statusMap && status == 0x41) {
            // Calculate MD5 hash with responded salt of the password
            const salt = chunk.slice(18, 34);
            console.log(`Received salt from server: ${salt.toString('hex')}`);
            const hash = crypto.createHash('md5').update(salt + password).digest();
            const authMsgBuffer = Buffer.alloc(52);
            authMsgBuffer.write('ESC/VP.net', 0, 'utf-8'); // Signature
            authMsgBuffer.writeUInt8(0x20, 10); // Protocol version (0x20 = 2.0)
            authMsgBuffer.writeUInt8(0x03, 11); // Message type (0x03 = CONNECTION)
            authMsgBuffer.writeUInt16BE(0x0000, 12); // Reserved (must be 0)
            authMsgBuffer.writeUInt8(0x00, 14); // Request
            authMsgBuffer.writeUInt8(0x02, 15); // Header number (2 additional headers)
            authMsgBuffer.writeUInt8(0x01, 16); // First header identifier (0x01 = Password)
            authMsgBuffer.writeUInt8(0x04, 17); // Header attributes (0x04 = MD5 Hash)
            hash.copy(authMsgBuffer, 18); // Request data (MD5 hash of salt + password) -> 16 bytes
            authMsgBuffer.writeUInt8(0x01, 34); // Second header identifier (0x01 = Password)
            authMsgBuffer.writeUInt8(0x05, 35); // Header attributes (0x05 = MD5 Hash)
            salt.copy(authMsgBuffer, 36); // Request data (Salt) -> 16 bytes
            console.log(`Sending authentication data to the server: ${authMsgBuffer.toString('hex')}`);
            client.write(authMsgBuffer);
        }
    }
});

client.on('end', function() {
    console.log('Requested an end to the TCP connection');
});

client.on('error', function(err) {
    console.error(`Error: ${err.message}`);
});
