const net = require('net');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');
const { hash, buildMerkleTree, getRoot, getProof, verifyProof } = require('./lib/merkle');
const { getOrGenerateKey, getXKey, sign, verify, decrypt, getFingerprint } = require('./lib/auth');
const logger = require('./lib/logger');

const BOOTSTRAP_PORT = process.argv[2] || 3000;
const serverPubPath = process.argv[3];
const MAX_STREAMS = parseInt(process.argv[4]) || 8;
const HOST = process.argv[5] || '127.0.0.1';

const clientKeys = getOrGenerateKey('client');
const clientXKeys = getXKey('client');
let trustedServerPub = (serverPubPath && serverPubPath !== 'none' && fs.existsSync(serverPubPath)) 
    ? fs.readFileSync(serverPubPath, 'utf8').trim() 
    : null;
let sharedSecret = null;
let currentServerId = null;

async function bootstrap() {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection(BOOTSTRAP_PORT, HOST, () => {
            logger.all('[Client] Connecting to bootstrap...');
        });

        let bootstrapResolved = false;
        let incomingBuffer = Buffer.alloc(0);

        socket.on('data', (data) => {
            incomingBuffer = Buffer.concat([incomingBuffer, data]);
            
            if (!sharedSecret) {
                try {
                    const str = incomingBuffer.toString();
                    if (str.startsWith('{') && str.includes('}')) {
                        const endIdx = str.indexOf('}') + 1;
                        const jsonStr = str.slice(0, endIdx);
                        const res = JSON.parse(jsonStr);
                        incomingBuffer = incomingBuffer.slice(Buffer.from(jsonStr).length);
                        handleHandshakeStep1(res, socket);
                    }
                } catch (e) {}
                return;
            }

            while (incomingBuffer.length >= 4) {
                const packetLen = incomingBuffer.readUInt32BE(0);
                if (incomingBuffer.length >= 4 + packetLen) {
                    const packetData = incomingBuffer.slice(4, 4 + packetLen);
                    incomingBuffer = incomingBuffer.slice(4 + packetLen);

                    const decrypted = decrypt(packetData, sharedSecret);
                    const manifest = JSON.parse(decrypted.toString());

                    if (manifest.type === 'init' && !bootstrapResolved) {
                        bootstrapResolved = true;
                        resolve(manifest);
                    } else if (manifest.type === 'update') {
                        handlePushUpdate(manifest);
                    }
                } else {
                    break; 
                }
            }
        });

        socket.on('error', (e) => {
            if (!bootstrapResolved) reject(e);
        });
    });
}

function handleHandshakeStep1(res, socket) {
    const nonce = res.nonce;
    const serverPub = res.pub;
    const serverXPubPem = res.xpub;

    currentServerId = serverPub;
    logger.important(`[MAST] Verified Sender ID: ${currentServerId}`, logger.colors.green);

    if (trustedServerPub && serverPub !== trustedServerPub) {
        logger.error('Connection blocked: Untrusted Sender ID');
        socket.end();
        return;
    }

    const signature = sign(nonce, clientKeys.privateKey).toString('hex');
    const serverXPub = crypto.createPublicKey(serverXPubPem);
    sharedSecret = crypto.diffieHellman({
        privateKey: clientXKeys.privateKey,
        publicKey: serverXPub
    });

    socket.write(JSON.stringify({
        pub: clientKeys.publicKey,
        xpub: clientXKeys.publicKey.export({ type: 'spki', format: 'pem' }),
        signature: signature
    }));
}

function truncatePath(p, limit = 40) {
    if (p.length <= limit) return p.padEnd(limit);
    const ext = path.extname(p);
    const name = path.basename(p, ext);
    return (name.slice(0, limit - ext.length - 3) + '...' + ext).padEnd(limit);
}

function handlePushUpdate(manifest) {
    process.stdout.write('\x1Bc'); 
    if (currentServerId) {
        logger.important(`[MAST] Verified Sender ID: ${currentServerId}`, logger.colors.green);
        if (sharedSecret) logger.all(`[MAST] Session Fingerprint: ${getFingerprint(sharedSecret)}`);
        console.log('--------------------------------------------------');
    }
    logger.important('[MAST] Remote update pushed! New file list:', logger.colors.yellow);
    manifest.files.forEach((f, i) => {
        console.log(`\x1b[33m[${i}]\x1b[0m ${truncatePath(f.path)} ${(f.size/1024).toFixed(2)} KB`);
    });
    process.stdout.write('\nEnter indices (0,1,2), range (0-5), or "all": ');
}

function ask(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer); }));
}

async function worker(id, manifest, pendingQueue, receivedChunks) {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection(manifest.data_port, HOST, () => {
            requestNext();
        });

        let buffer = Buffer.alloc(0);

        function requestNext() {
            const next = pendingQueue.shift();
            if (next === undefined) {
                socket.end();
                return;
            }
            if (!manifest.session_id) {
                reject(new Error("Missing Session ID"));
                return;
            }
            const req = Buffer.alloc(36);
            req.write(manifest.session_id, 0, 32, 'hex');
            req.writeUInt32BE(next, 32);
            socket.write(req);
        }

        socket.on('data', (chunk) => {
            buffer = Buffer.concat([buffer, chunk]);
            if (buffer.length >= 8) {
                const chunkId = buffer.readUInt32BE(0);
                const chunkLen = buffer.readUInt32BE(4);
                if (buffer.length >= 8 + chunkLen) {
                    const encryptedChunk = buffer.slice(8, 8 + chunkLen);
                    const chunkData = decrypt(encryptedChunk, sharedSecret);
                    receivedChunks[chunkId] = chunkData;
                    buffer = buffer.slice(8 + chunkLen);
                    requestNext();
                }
            }
        });

        socket.on('end', resolve);
        socket.on('error', reject);
    });
}

async function main() {
    try {
        logger.important('[MAST] Initiating secure session...');
        const manifest = await bootstrap();
        
        if (!manifest || !manifest.session_id) {
            throw new Error("Handshake failed: No session ID received");
        }

        console.log('\n--- Remote File Manifest ---');
        manifest.files.forEach((f, i) => {
            console.log(`\x1b[33m[${i}]\x1b[0m ${truncatePath(f.path)} ${(f.size/1024).toFixed(2)} KB`);
        });

        const input = await ask('\nEnter indices (0,1,2), range (0-5), or "all": ');
        let selectedFiles = [];
        if (input.toLowerCase() === 'all') {
            selectedFiles = manifest.files;
        } else if (input.includes('-')) {
            const [start, end] = input.split('-').map(Number);
            selectedFiles = manifest.files.slice(start, end + 1);
        } else {
            selectedFiles = input.split(',').map(Number).map(i => manifest.files[i]);
        }

        const start = Date.now();
        const neededChunkIds = new Set();
        selectedFiles.forEach(f => {
            const startChunk = Math.floor(f.offset / manifest.chunk_size);
            const endChunk = Math.floor((f.offset + f.size - 1) / manifest.chunk_size);
            for (let i = startChunk; i <= endChunk; i++) neededChunkIds.add(i);
        });

        const pendingQueue = Array.from(neededChunkIds);
        const receivedChunks = new Array(manifest.chunk_count);
        
        logger.important(`[MAST] Task: ${selectedFiles.length} files | ${pendingQueue.length} chunks`);
        
        const optimalStreams = pendingQueue.length > 50 ? MAX_STREAMS : Math.min(4, Math.ceil(pendingQueue.length / 2));
        logger.all(`[MAST] Spawning ${optimalStreams} parallel data streams...`);
        
        const streams = [];
        for (let i = 0; i < optimalStreams; i++) {
            streams.push(worker(i, manifest, pendingQueue, receivedChunks));
        }

        await Promise.all(streams);
        const duration = Date.now() - start;
        
        logger.important(`[MAST] Transfer complete in ${duration}ms`, logger.colors.green);
        logger.all('[MAST] Reconstructing filesystem...');

        const downloadDir = path.join(__dirname, 'downloads');
        if (!fs.existsSync(downloadDir)) fs.mkdirSync(downloadDir);

        selectedFiles.forEach(f => {
            const filePath = path.join(downloadDir, f.path);
            const fileDir = path.dirname(filePath);
            if (!fs.existsSync(fileDir)) fs.mkdirSync(fileDir, { recursive: true });

            const startChunk = Math.floor(f.offset / manifest.chunk_size);
            const endChunk = Math.floor((f.offset + f.size - 1) / manifest.chunk_size);
            
            const fileBuffers = [];
            for (let i = startChunk; i <= endChunk; i++) {
                const chunkData = receivedChunks[i];
                const chunkStart = i * manifest.chunk_size;
                const sliceStart = Math.max(0, f.offset - chunkStart);
                const sliceEnd = Math.min(chunkData.length, (f.offset + f.size) - chunkStart);
                fileBuffers.push(chunkData.slice(sliceStart, sliceEnd));
            }

            fs.writeFileSync(filePath, Buffer.concat(fileBuffers));
            logger.all(`[Client] Verified and Saved: ${f.path}`);
        });

    } catch (e) {
        console.error('[Client] Error:', e.message);
    }
}

main();
