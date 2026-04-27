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

function computeFileHash(filePath) {
    try {
        const data = fs.readFileSync(filePath);
        return crypto.createHash('sha256').update(data).digest('hex');
    } catch (e) {
        return null;
    }
}

function verifyManifest(manifest, serverPubHex) {
    try {
        if (!manifest.manifest_sig || !serverPubHex) return false;
        const payload = manifest.master_hash + manifest.files.map(f => f.path + ':' + (f.sha256 || '')).join('|');
        return verify(payload, Buffer.from(manifest.manifest_sig, 'hex'), serverPubHex);
    } catch (e) {
        return false;
    }
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
const MAX_STREAMS = parseInt(getArg('--streams', '-s', process.argv[4] || 16));
const HOST = getArg('--host', '-H', process.argv[5] || '127.0.0.1');

const clientKeys = getOrGenerateKey('client');
const clientXKeys = getXKey('client');
let trustedServerPub = (serverPubPath && serverPubPath !== 'none' && fs.existsSync(serverPubPath))
    ? fs.readFileSync(serverPubPath, 'utf8').trim()
    : null;
let sharedSecret = null;
let currentServerId = null;
let globalManifest = null;
let globalCurrentDir = '';
let updateReceived = false;

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
                              
██▄  ▄██ ▄████▄ ▄█████ ██████ 
██ ▀▀ ██ ██▄▄██ ▀▀▀▄▄▄   ██   
██    ██ ██  ██ █████▀   ██   
                              
\x1b[0m`);
    logger.important('--------------------------------------------------');
}

const fdCache = new Map();
function getCachedFd(filePath, mode = 'r') {
    const key = `${filePath}:${mode}`;
    if (fdCache.has(key)) return fdCache.get(key);
    try {
        const fd = fs.openSync(filePath, mode);
        fdCache.set(key, fd);
        return fd;
    } catch (e) {
        return null;
    }
}

function clearFdCache() {
    for (const [key, fd] of fdCache.entries()) {
        try { fs.closeSync(fd); } catch (e) { }
    }
    fdCache.clear();
}

let lastSpeedUpdate = Date.now();
let lastCompleted = 0;
let currentMbps = 0;

function drawProgressBar(completed, total, chunkSize) {
    const now = Date.now();
    const elapsed = (now - lastSpeedUpdate) / 1000;
    if (elapsed >= 1) {
        const delta = completed - lastCompleted;
        currentMbps = (delta * (chunkSize || 64 * 1024) * 16) / (1024 * 1024) / elapsed;
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

let bootstrapSocket = null;
let serverDisconnected = false;
let reconnecting = false;

async function bootstrap() {
    return new Promise((resolve, reject) => {
        function connect() {
            if (reconnecting) return;
            serverDisconnected = false;

            const socket = net.createConnection(BOOTSTRAP_PORT, HOST, () => {
                bootstrapSocket = socket;
                if (!sharedSecret) {
                    startThrobber('Connecting to bootstrap server & negotiating handshake...');
                } else {
                    startThrobber('Reconnected to server...');
                }
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
                            if (!verifyManifest(manifest, currentServerId)) {
                                stopThrobber();
                                reject(new Error('Manifest signature verification failed — possible tampering'));
                                return;
                            }
                            globalManifest = manifest;
                            bootstrapResolved = true;
                            stopThrobber();
                            resolve(manifest);
                        } else if (manifest.type === 'merkle') {
                        } else if (manifest.type === 'update') {
                            if (!verifyManifest(manifest, currentServerId)) {
                                logger.error('[MAST] Update manifest signature invalid — ignoring');
                                return;
                            }
                            if (manifest.reset_dir) {
                                globalCurrentDir = '';
                                clearFdCache();
                            }
                            globalManifest = { ...globalManifest, ...manifest };
                            stopThrobber();
                            handlePushUpdate(manifest);
                        }
                    } else {
                        break;
                    }
                }
            });

            socket.on('error', (e) => {
                if (!bootstrapResolved) {
                    stopThrobber();
                    if (!serverDisconnected) {
                        serverDisconnected = true;
                        logger.error(`[MAST] Connection to server lost: ${e.message}`);
                        logger.important('[MAST] Waiting for server to come back online...', logger.colors.yellow);
                    }
                    bootstrapSocket = null;
                    setTimeout(connect, 3000);
                }
            });

            socket.on('close', () => {
                if (bootstrapSocket === socket) {
                    bootstrapSocket = null;
                }
                if (!serverDisconnected && !bootstrapResolved) {
                    serverDisconnected = true;
                    logger.error('[MAST] Server disconnected');
                    logger.important('[MAST] Waiting for server to come back online...', logger.colors.yellow);
                    setTimeout(connect, 3000);
                }
            });
        }

        connect();
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
    logger.important(`[MAST] Session Fingerprint: ${fingerprint}`);
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
    serverDisconnected = false;
    if (currentServerId) {
        logger.important(`[MAST] Verified Sender ID: ${currentServerId.slice(0, 64)}...`, logger.colors.green);
        if (sharedSecret) logger.important(`[MAST] Session Fingerprint: ${getFingerprint(sharedSecret)}`);
        console.log('--------------------------------------------------');
    }
    logger.important('[MAST] Remote update pushed!\nPress any key to continue...', logger.colors.yellow);
    if (manifest.reset_dir) {
        logger.important('[MAST] Server changed directory. Reset to root.', logger.colors.cyan);
    }
    updateReceived = true;
}

function ask(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer); }));
}

async function worker(id, manifest, selectedFiles, pendingQueue, downloadDir, onProgress) {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection({ port: manifest.data_port, host: HOST });
        let buffer = Buffer.alloc(0);
        let inFlight = 0;
        const PIPELINE_DEPTH = 20;

        function fillPipeline() {
            while (inFlight < PIPELINE_DEPTH && pendingQueue.length > 0) {
                const next = pendingQueue.shift();
                if (!manifest.session_id) {
                    reject(new Error("Missing Session ID"));
                    return;
                }
                const req = Buffer.alloc(36);
                req.write(manifest.session_id, 0, 32, 'hex');
                req.writeUInt32BE(next, 32);
                socket.write(req);
                inFlight++;
            }
            if (inFlight === 0 && pendingQueue.length === 0) {
                socket.end();
            }
        }

        socket.on('connect', fillPipeline);

        socket.on('data', (chunk) => {
            buffer = Buffer.concat([buffer, chunk]);
            while (buffer.length >= 8) {
                const chunkId = buffer.readUInt32BE(0);
                const chunkLen = buffer.readUInt32BE(4);
                if (buffer.length >= 8 + chunkLen) {
                    const encryptedChunk = buffer.slice(8, 8 + chunkLen);
                    const chunkData = decrypt(encryptedChunk, sharedSecret);

                    const chunkStart = chunkId * manifest.chunk_size;
                    selectedFiles.forEach(f => {
                        const fileStart = f.offset;
                        const fileEnd = f.offset + f.size;
                        if (chunkStart + chunkData.length > fileStart && chunkStart < fileEnd) {
                            const sliceStart = Math.max(0, fileStart - chunkStart);
                            const sliceEnd = Math.min(chunkData.length, fileEnd - chunkStart);
                            const writeStartInFile = Math.max(0, chunkStart - fileStart);

                            const filePath = path.join(downloadDir, f.path);
                            try {
                                const fd = getCachedFd(filePath, 'r+');
                                if (fd) fs.writeSync(fd, chunkData, sliceStart, sliceEnd - sliceStart, writeStartInFile);
                            } catch (err) {
                                logger.error(`[Worker ${id}] Failed to write to ${f.path}: ${err.message}`);
                            }
                        }
                    });

                    buffer = buffer.slice(8 + chunkLen);
                    inFlight--;
                    onProgress();
                } else {
                    break;
                }
            }
            fillPipeline();
        });

        socket.on('end', resolve);
        socket.on('error', (err) => {
            console.error(`[Worker ${id}] Connection error: ${err.message}`);
            resolve();
        });
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

            if (serverDisconnected) {
                await new Promise(resolve => setTimeout(resolve, 1000));
                continue;
            }

            if (updateReceived) {
                updateReceived = false;
                await new Promise(resolve => setTimeout(resolve, 500));
                continue;
            }

            if (!globalManifest || !globalManifest.files) {
                await new Promise(resolve => setTimeout(resolve, 1000));
                continue;
            }

            console.log(`\n--- Remote File Manifest [/${globalCurrentDir}] ---`);

            const viewItems = [];
            const dirs = new Set();
            const prefix = globalCurrentDir ? globalCurrentDir + '/' : '';

            globalManifest.files.forEach((f, globalIndex) => {
                if (f.path.startsWith(prefix)) {
                    const remainder = f.path.slice(prefix.length);
                    const slashIdx = remainder.indexOf('/');
                    if (slashIdx === -1) {
                        viewItems.push({ type: 'file', name: remainder, size: f.size, file: f });
                    } else {
                        const dirName = remainder.slice(0, slashIdx);
                        if (!dirs.has(dirName)) {
                            dirs.add(dirName);
                            viewItems.push({ type: 'dir', name: dirName + '/', size: 0, globalIndices: [globalIndex] });
                        } else {
                            const dirItem = viewItems.find(i => i.type === 'dir' && i.name === dirName + '/');
                            dirItem.globalIndices.push(globalIndex);
                        }
                    }
                }
            });

            viewItems.forEach((item, i) => {
                if (item.type === 'dir') {
                    console.log(`\x1b[36m[${i}]\x1b[0m \x1b[34m${item.name}\x1b[0m`);
                } else {
                    console.log(`\x1b[33m[${i}]\x1b[0m ${truncatePath(item.name)} ${formatBytes(item.size)}`);
                }
            });

            const input = await ask('\nEnter indices (0,1,2), range (0-5), "all", "cd <dir>", "cd ..", or "q" to quit: ');
            const cmd = input.trim();
            if (cmd.toLowerCase() === 'q') process.exit(0);
            if (!cmd) continue;

            if (cmd.startsWith('cd ')) {
                const target = cmd.slice(3).trim();
                if (target === '..') {
                    if (globalCurrentDir) {
                        const parts = globalCurrentDir.split('/');
                        parts.pop();
                        globalCurrentDir = parts.join('/');
                    }
                } else if (target === '/') {
                    globalCurrentDir = '';
                } else {
                    const dirItem = viewItems.find(i => i.type === 'dir' && i.name === target + '/');
                    if (dirItem) {
                        globalCurrentDir = globalCurrentDir ? globalCurrentDir + '/' + target : target;
                    } else {
                        console.log(`\n\x1b[31mDirectory not found: ${target}\x1b[0m`);
                    }
                }
                process.stdout.write('\x1Bc');
                printHeader();
                if (currentServerId) {
                    logger.important(`[MAST] Verified Sender ID: ${currentServerId.slice(0, 64)}...`, logger.colors.green);
                    if (sharedSecret) logger.important(`[MAST] Session Fingerprint: ${getFingerprint(sharedSecret)}`);
                    console.log('--------------------------------------------------');
                }
                continue;
            }

            let selectedFiles = [];
            if (cmd.toLowerCase() === 'all') {
                viewItems.forEach(item => {
                    if (item.type === 'file') selectedFiles.push(item.file);
                    else if (item.type === 'dir') {
                        item.globalIndices.forEach(gi => selectedFiles.push(globalManifest.files[gi]));
                    }
                });
            } else if (cmd.includes('-')) {
                const [startIdx, endIdx] = cmd.split('-').map(Number);
                for (let i = startIdx; i <= endIdx; i++) {
                    const item = viewItems[i];
                    if (item) {
                        if (item.type === 'file') selectedFiles.push(item.file);
                        else if (item.type === 'dir') item.globalIndices.forEach(gi => selectedFiles.push(globalManifest.files[gi]));
                    }
                }
            } else {
                const indices = cmd.split(',').map(Number).filter(i => !isNaN(i) && viewItems[i]);
                indices.forEach(i => {
                    const item = viewItems[i];
                    if (item.type === 'file') selectedFiles.push(item.file);
                    else if (item.type === 'dir') {
                        item.globalIndices.forEach(gi => selectedFiles.push(globalManifest.files[gi]));
                    }
                });
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

            const identicalFiles = [];
            const changedFiles = [];
            const skippedByUser = new Set();

            selectedFiles.forEach(f => {
                const filePath = path.join(downloadDir, f.path);
                if (fs.existsSync(filePath)) {
                    const localHash = computeFileHash(filePath);
                    const remoteHash = f.sha256 || null;
                    if (localHash && remoteHash && localHash === remoteHash) {
                        identicalFiles.push(f);
                    } else {
                        changedFiles.push({ f, localHash, remoteHash });
                    }
                }
            });

            if (identicalFiles.length > 0) {
                logger.important(`[MAST] ${identicalFiles.length} file(s) already up to date — skipping:`, logger.colors.green);
                identicalFiles.forEach(f => console.log(`  \x1b[32m✓\x1b[0m ${f.path}`));
            }

            if (changedFiles.length > 0) {
                console.log();
                logger.important(`[MAST] ${changedFiles.length} file(s) differ from remote:`, logger.colors.yellow);
                for (const { f, localHash, remoteHash } of changedFiles) {
                    console.log(`  \x1b[33m⚠\x1b[0m ${f.path} (${formatBytes(f.size)})`);
                    console.log(`    \x1b[90mLocal  SHA-256: ${localHash || 'unreadable'}\x1b[0m`);
                    console.log(`    \x1b[90mRemote SHA-256: ${remoteHash || 'unavailable'}\x1b[0m`);
                }
                const answer = await ask('\nOverwrite changed file(s)? (yes/no/select): ');
                if (answer.toLowerCase() === 'select') {
                    for (const { f, localHash, remoteHash } of changedFiles) {
                        const yn = await ask(`  Overwrite ${f.path}? (yes/no): `);
                        if (yn.toLowerCase() !== 'yes' && yn.toLowerCase() !== 'y') skippedByUser.add(f.path);
                    }
                } else if (answer.toLowerCase() !== 'yes' && answer.toLowerCase() !== 'y') {
                    changedFiles.forEach(({ f }) => skippedByUser.add(f.path));
                }
            }

            selectedFiles = selectedFiles.filter(f => {
                if (identicalFiles.includes(f)) return false;
                if (skippedByUser.has(f.path)) return false;
                return true;
            });
            if (selectedFiles.length === 0) {
                logger.important('[MAST] Nothing to download.', logger.colors.cyan);
                continue;
            }

            neededChunkIds.clear();
            selectedFiles.forEach(f => {
                const startChunk = Math.floor(f.offset / globalManifest.chunk_size);
                const endChunk = Math.floor((f.offset + f.size - 1) / globalManifest.chunk_size);
                for (let i = startChunk; i <= endChunk; i++) neededChunkIds.add(i);
            });

            try {
                selectedFiles.forEach(f => {
                    const filePath = path.join(downloadDir, f.path);
                    const fileDir = path.dirname(filePath);
                    if (!fs.existsSync(fileDir)) fs.mkdirSync(fileDir, { recursive: true });

                    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
                    const fd = fs.openSync(filePath, 'w');
                    if (f.size > 0) {
                        fs.writeSync(fd, Buffer.alloc(1), 0, 1, f.size - 1);
                    }
                    fs.closeSync(fd);
                });
            } catch (e) {
                logger.error(`[MAST] File pre-allocation failed: ${e.message}`);
                continue;
            }

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
                streams.push(worker(i, globalManifest, selectedFiles, pendingQueue, downloadDir, () => {
                    completedChunks++;
                    drawProgressBar(completedChunks, totalChunks, globalManifest.chunk_size);
                }));
            }
            await Promise.all(streams);
            const duration = Date.now() - start;
            console.log();
            logger.important(`[MAST] Transfer complete in ${duration}ms | ${optimalStreams} streams | ${HOST}:${globalManifest.data_port}`, logger.colors.green);
            logger.all('[MAST] Verified and Saved files.');

            await ask('\nPress Enter to continue downloading...');
            process.stdout.write('\x1Bc');
        }
    } catch (e) {
        console.error('[Client] Error:', e.message);
    }
}
main();