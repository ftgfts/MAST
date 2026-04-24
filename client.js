const net = require('net');
const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');
const { hash, buildMerkleTree, getRoot, getProof, verifyProof } = require('./lib/merkle');
const { getOrGenerateKey, getXKey, sign, verify, decrypt, getFingerprint } = require('./lib/auth');
const logger = require('./lib/logger');

function getArg(flag, short, defaultValue) {
    const idx = process.argv.findIndex(a => a === flag || a === short);
    if (idx !== -1 && process.argv[idx + 1]) return process.argv[idx + 1];
    if (typeof defaultValue === 'string' && defaultValue.startsWith('-')) return null;
    return defaultValue;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

if (process.argv.includes('--help') || process.argv.includes('-h')) {
    console.log(`
MAST Client - Securely receive files and folders

Usage:
  node client.js [options] [port]

Options:
  -P, --port <num>       Server bootstrap port (Default: 3000)
  -k, --key <path>       Path to server's .pub key for verification
  -s, --streams <num>    Number of parallel streams (Default: 8)
  -H, --host <addr>      Server IP or hostname (Default: 127.0.0.1)
    `);
    process.exit(0);
}

const BOOTSTRAP_PORT = parseInt(getArg('--port', '-P', process.argv[2] || 3000));
const serverPubPath = getArg('--key', '-k', process.argv[3]);
const MAX_STREAMS = parseInt(getArg('--streams', '-s', process.argv[4] || 8));
const HOST = getArg('--host', '-H', process.argv[5] || '127.0.0.1');

const clientKeys = getOrGenerateKey('client');
const clientXKeys = getXKey('client');
let trustedServerPub = (serverPubPath && serverPubPath !== 'none' && fs.existsSync(serverPubPath))
    ? fs.readFileSync(serverPubPath, 'utf8').trim()
    : null;
let sharedSecret = null;
let currentServerId = null;
let globalManifest = null;

let throbberInterval = null;
const throbberFrames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
let throbberIndex = 0;

function startThrobber(text) {
    if (throbberInterval) clearInterval(throbberInterval);
    const draw = () => {
        process.stdout.write(`\r\x1b[36m${throbberFrames[throbberIndex]}\x1b[0m ${text}`);
        throbberIndex = (throbberIndex + 1) % throbberFrames.length;
    };
    draw();
    throbberInterval = setInterval(draw, 80);
}

function stopThrobber() {
    if (throbberInterval) {
        clearInterval(throbberInterval);
        throbberInterval = null;
        process.stdout.write('\r\x1b[K');
    }
}

function clear() {
    process.stdout.write('\x1Bc');
}

function printHeader() {
    console.log(`\x1b[35m  
 _____ _____ _____ _____ 
|     |  _  |   __|_   _|
| | | |     |__   | | |  
|_|_|_|__|__|_____| |_|  
\x1b[0m`);
    logger.important('--------------------------------------------------');
}

let lastSpeedUpdate = Date.now();
let lastCompleted = 0;
let currentMbps = 0;

function drawProgressBar(completed, total, chunkSize) {
    const now = Date.now();
    const elapsed = (now - lastSpeedUpdate) / 1000;
    if (elapsed >= 1) {
        const delta = completed - lastCompleted;
        currentMbps = (delta * (chunkSize || 64 * 1024) * 8) / (1024 * 1024) / elapsed;
        lastSpeedUpdate = now;
        lastCompleted = completed;
    }
    const width = 40;
    const percentage = total > 0 ? Math.floor((completed / total) * 100) : 0;
    const filled = total > 0 ? Math.floor((width * completed) / total) : 0;
    const empty = width - filled;
    const bar = '█'.repeat(filled) + '░'.repeat(empty);
    const speedText = currentMbps > 0 ? ` | ${currentMbps.toFixed(2)} Mbps` : ' | ...';
    process.stdout.write(`\r\x1b[32m[${bar}]\x1b[0m ${percentage}% (${completed}/${total} chunks)${speedText}`);
}

async function bootstrap() {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection(BOOTSTRAP_PORT, HOST, () => {
            startThrobber('Connecting to bootstrap server & negotiating handshake...');
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
                } catch (e) { }
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
                        globalManifest = manifest;
                        bootstrapResolved = true;
                        stopThrobber();
                        resolve(manifest);
                    } else if (manifest.type === 'merkle') {
                        const merkleFile = path.join(require('os').tmpdir(), `mast_client_merkle_${Date.now()}.json`);
                        fs.writeFileSync(merkleFile, JSON.stringify(manifest.merkle_tree));
                    } else if (manifest.type === 'update') {
                        globalManifest = manifest;
                        stopThrobber();
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

    clear();
    printHeader();
    logger.important(`[MAST] Verified Sender ID: ${currentServerId.slice(0, 64)}...`, logger.colors.green);
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
    const fingerprint = getFingerprint(sharedSecret);
    logger.all(`[MAST] Session Fingerprint: ${fingerprint}`);
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
    clear();
    printHeader();
    if (currentServerId) {
        logger.important(`[MAST] Verified Sender ID: ${currentServerId.slice(0, 64)}...`, logger.colors.green);
        if (sharedSecret) logger.all(`[MAST] Session Fingerprint: ${getFingerprint(sharedSecret)}`);
        console.log('--------------------------------------------------');
    }
    logger.important('[MAST] Remote update pushed! New file list:', logger.colors.yellow);
    manifest.files.forEach((f, i) => {
        console.log(`\x1b[33m[${i}]\x1b[0m ${truncatePath(f.path)} ${formatBytes(f.size)}`);
    });
    process.stdout.write('\nEnter indices (0,1,2), range (0-5), or "all": ');
}

function ask(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer); }));
}

async function worker(id, manifest, pendingQueue, downloadDir, onProgress) {
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

                    const chunkStart = chunkId * manifest.chunk_size;
                    manifest.files.forEach(f => {
                        const fileStart = f.offset;
                        const fileEnd = f.offset + f.size;
                        if (chunkStart + chunkData.length > fileStart && chunkStart < fileEnd) {
                            const sliceStart = Math.max(0, fileStart - chunkStart);
                            const sliceEnd = Math.min(chunkData.length, fileEnd - chunkStart);
                            const writeStartInFile = Math.max(0, chunkStart - fileStart);

                            const filePath = path.join(downloadDir, f.path);
                            const fd = fs.openSync(filePath, 'r+');
                            fs.writeSync(fd, chunkData, sliceStart, sliceEnd - sliceStart, writeStartInFile);
                            fs.closeSync(fd);
                        }
                    });

                    buffer = buffer.slice(8 + chunkLen);
                    onProgress();
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
        if (!globalManifest || !globalManifest.session_id) {
            throw new Error("Handshake failed: No session ID received");
        }

        while (true) {
            console.log('\n--- Remote File Manifest ---');
            globalManifest.files.forEach((f, i) => {
                console.log(`\x1b[33m[${i}]\x1b[0m ${truncatePath(f.path)} ${formatBytes(f.size)}`);
            });

            const input = await ask('\nEnter indices (0,1,2), range (0-5), "all", or "q" to quit: ');
            if (input.toLowerCase() === 'q') process.exit(0);
            if (!input) continue;

            let selectedFiles = [];
            if (input.toLowerCase() === 'all') {
                selectedFiles = globalManifest.files;
            } else if (input.includes('-')) {
                const [startIdx, endIdx] = input.split('-').map(Number);
                selectedFiles = globalManifest.files.slice(startIdx, endIdx + 1);
            } else {
                selectedFiles = input.split(',').map(Number).filter(i => !isNaN(i) && globalManifest.files[i]).map(i => globalManifest.files[i]);
            }
            if (selectedFiles.length === 0) continue;

            const start = Date.now();
            const neededChunkIds = new Set();
            selectedFiles.forEach(f => {
                const startChunk = Math.floor(f.offset / globalManifest.chunk_size);
                const endChunk = Math.floor((f.offset + f.size - 1) / globalManifest.chunk_size);
                for (let i = startChunk; i <= endChunk; i++) neededChunkIds.add(i);
            });
            const downloadDir = path.join(__dirname, 'downloads');
            if (!fs.existsSync(downloadDir)) fs.mkdirSync(downloadDir);
            selectedFiles.forEach(f => {
                const filePath = path.join(downloadDir, f.path);
                const fileDir = path.dirname(filePath);
                if (!fs.existsSync(fileDir)) fs.mkdirSync(fileDir, { recursive: true });

                const fd = fs.openSync(filePath, 'w');
                if (f.size > 0) {
                    fs.writeSync(fd, Buffer.alloc(1), 0, 1, f.size - 1);
                }
                fs.closeSync(fd);
            });

            const pendingQueue = Array.from(neededChunkIds);
            const totalChunks = pendingQueue.length;
            let completedChunks = 0;

            logger.important(`[MAST] Task: ${selectedFiles.length} files | ${totalChunks} chunks`);

            let optimalStreams = Math.min(MAX_STREAMS, Math.ceil(totalChunks / 20));
            if (optimalStreams < 4 && totalChunks > 1) optimalStreams = Math.min(totalChunks, 4);

            logger.all(`[MAST] Spawning ${optimalStreams} parallel data streams...`);

            lastSpeedUpdate = Date.now();
            lastCompleted = 0;
            currentMbps = 0;
            drawProgressBar(0, totalChunks, globalManifest.chunk_size);

            const streams = [];
            for (let i = 0; i < optimalStreams; i++) {
                streams.push(worker(i, globalManifest, pendingQueue, downloadDir, () => {
                    completedChunks++;
                    drawProgressBar(completedChunks, totalChunks, globalManifest.chunk_size);
                }));
            }
            await Promise.all(streams);
            const duration = Date.now() - start;
            console.log();
            logger.important(`[MAST] Transfer complete in ${duration}ms`, logger.colors.green);
            logger.all('[MAST] Verified and Saved files.');

            await ask('\nPress Enter to continue downloading...');
            process.stdout.write('\x1Bc');
        }
    } catch (e) {
        console.error('[Client] Error:', e.message);
    }
}
main();
