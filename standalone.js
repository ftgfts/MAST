/**
 * MAST STANDALONE - Unified Server, Client, and Wrapper
 */
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

// Libraries
const { hash, buildMerkleTree, getRoot, getProof, verifyProof } = require('./lib/merkle');
const { prepareDataset } = require('./lib/files');
const { getOrGenerateKey, getXKey, sign, verify, encrypt, decrypt, getFingerprint } = require('./lib/auth');
const logger = require('./lib/logger');

const command = process.argv[2];

// --- UTILITIES ---
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

function ask(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => rl.question(question, answer => { rl.close(); resolve(answer); }));
}

function clear() {
    process.stdout.write('\x1Bc');
}

function printHeader() {
    console.log(`\x1b[35m
   __  ___   ___   _____
  /  |/  /  / _ | / ___/
 / /|_/ /  / __ | \\___ \\ 
/_/  /_/  /_/ |_|/____/  (Merkle Addressed Streaming Transfer)
\x1b[0m`);
    logger.important('--------------------------------------------------');
}

// --- THROBBER ---
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

// --- SERVER ENGINE ---
async function runServer(pathArg, keyPath, streamArg, portArg) {
    const targetPath = pathArg || './';
    const clientPubPath = keyPath;
    const STREAM_COUNT = parseInt(streamArg) || 4;
    const DEFAULT_BOOTSTRAP_PORT = parseInt(portArg) || 3000;

    if (!fs.existsSync(targetPath)) {
        logger.error(`Target not found: ${targetPath}`);
        return;
    }

    const serverKeys = getOrGenerateKey('server');
    const serverXKeys = getXKey('server');
    let authorizedClientPub = clientPubPath ? fs.readFileSync(clientPubPath, 'utf8') : null;

    clear();
    printHeader();
    logger.important(`[MAST] Initialized ID: ${serverKeys.publicKey.slice(0, 64)}...`);

    startThrobber('[MAST] Preparing dataset and building Merkle tree...');
    let dataset = prepareDataset(targetPath);
    let tree = await buildMerkleTree(dataset);
    let masterHash = getRoot(tree).toString('hex');
    stopThrobber();

    const activeSessions = new Map();
    const subscribers = new Set();

    logger.important(`[MAST] Ready: ${dataset.manifestFiles.length} files | ${dataset.chunkCount} chunks | ${formatBytes(dataset.totalSize)}`, logger.colors.green);

    async function broadcastUpdate() {
        stopThrobber();
        logger.important('[MAST] Change detected! Rebuilding...', logger.colors.yellow);
        startThrobber('[MAST] Rebuilding dataset and Merkle tree...');
        dataset = prepareDataset(targetPath);
        tree = await buildMerkleTree(dataset);
        masterHash = getRoot(tree).toString('hex');
        stopThrobber();
        const manifest = {
            type: 'update',
            total_size: dataset.totalSize,
            chunk_count: dataset.chunkCount,
            chunk_size: dataset.CHUNK_SIZE,
            master_hash: masterHash,
            files: dataset.manifestFiles
        };
        for (const sub of subscribers) {
            try {
                const encrypted = encrypt(Buffer.from(JSON.stringify(manifest)), sub.secret);
                const packet = Buffer.alloc(4);
                packet.writeUInt32BE(encrypted.length, 0);
                sub.socket.write(packet);
                sub.socket.write(encrypted);
            } catch (e) { subscribers.delete(sub); }
        }
    }

    if (fs.statSync(targetPath).isDirectory()) {
        let watchTimeout;
        fs.watch(targetPath, { recursive: true }, (event, filename) => {
            if (filename) {
                clearTimeout(watchTimeout);
                watchTimeout = setTimeout(broadcastUpdate, 500);
            }
        });
    }

    const dataServer = net.createServer((socket) => {
        socket.on('data', (data) => {
            if (data.length < 36) return;
            const sessionId = data.slice(0, 32).toString('hex');
            const chunkId = data.readUInt32BE(32);
            const session = activeSessions.get(sessionId);
            if (!session) return;
            if (chunkId < dataset.chunkCount) {
                const { readChunk } = require('./lib/files');
                const chunkData = readChunk(dataset, chunkId);
                const encryptedChunk = encrypt(chunkData, session.secret);
                const header = Buffer.alloc(8);
                header.writeUInt32BE(chunkId, 0);
                header.writeUInt32BE(encryptedChunk.length, 4);
                socket.write(header);
                socket.write(encryptedChunk);
            }
        });
    });

    dataServer.listen(0, '::', () => {
        const dataPort = dataServer.address().port;
        logger.important(`[MAST] Data pool active on [::]:${dataPort}`);
        const bootstrapServer = net.createServer((socket) => {
            const nonce = crypto.randomBytes(32);
            socket.write(JSON.stringify({ 
                nonce: nonce.toString('hex'), 
                pub: serverKeys.publicKey, 
                xpub: serverXKeys.publicKey.export({ type: 'spki', format: 'pem' }) 
            }));
            socket.on('data', (data) => {
                try {
                    const res = JSON.parse(data.toString());
                    if (!res.signature) return;
                    if (authorizedClientPub && res.pub !== authorizedClientPub) return socket.end();
                    if (!verify(nonce.toString('hex'), res.signature, res.pub)) return socket.end();
                    const secret = crypto.diffieHellman({
                        privateKey: serverXKeys.privateKey,
                        publicKey: crypto.createPublicKey(res.xpub)
                    });
                    const sessionId = crypto.randomBytes(32).toString('hex');
                    activeSessions.set(sessionId, { secret, clientPub: res.pub });
                    logger.important(`[MAST] Handshake complete: ${getFingerprint(secret)}`, logger.colors.green);
                    const manifest = {
                        type: 'init',
                        session_id: sessionId,
                        total_size: dataset.totalSize,
                        chunk_count: dataset.chunkCount,
                        chunk_size: dataset.CHUNK_SIZE,
                        stream_count: STREAM_COUNT,
                        data_port: dataPort,
                        master_hash: masterHash,
                        files: dataset.manifestFiles
                    };
                    const enc = encrypt(Buffer.from(JSON.stringify(manifest)), secret);
                    const pkt = Buffer.alloc(4); pkt.writeUInt32BE(enc.length, 0);
                    socket.write(pkt); socket.write(enc);
                    
                    const merkleData = {
                        type: 'merkle',
                        merkle_tree: tree.map(level => level.map(node => node.toString('hex')))
                    };
                    const encMerkle = encrypt(Buffer.from(JSON.stringify(merkleData)), secret);
                    const merklePkt = Buffer.alloc(4); merklePkt.writeUInt32BE(encMerkle.length, 0);
                    socket.write(merklePkt); socket.write(encMerkle);
                    
                    subscribers.add({ socket, secret });
                } catch (e) {}
            });
        });
        bootstrapServer.listen(DEFAULT_BOOTSTRAP_PORT, '::', () => {
            logger.important(`[MAST] Listening on port ${DEFAULT_BOOTSTRAP_PORT}`);
        });
    });
}

// --- CLIENT ENGINE ---
async function runClient(portArg, keyPath, streamArg, hostArg) {
    const BOOTSTRAP_PORT = parseInt(portArg) || 3000;
    const HOST = hostArg || '127.0.0.1';
    const MAX_STREAMS = parseInt(streamArg) || 8;
    const clientKeys = getOrGenerateKey('client');
    const clientXKeys = getXKey('client');
    let sharedSecret = null;
    let currentServerId = null;
    let globalManifest = null;

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
        const bar = '█'.repeat(filled) + '░'.repeat(width - filled);
        const speedText = currentMbps > 0 ? ` | ${currentMbps.toFixed(2)} Mbps` : ' | ...';
        process.stdout.write(`\r\x1b[32m[${bar}]\x1b[0m ${percentage}% (${completed}/${total} chunks)${speedText}`);
    }

    async function bootstrap() {
        return new Promise((resolve) => {
            const socket = net.createConnection(BOOTSTRAP_PORT, HOST, () => {
                startThrobber('Connecting to bootstrap server & negotiating handshake...');
            });
            let incomingBuffer = Buffer.alloc(0);
            socket.on('data', (data) => {
                incomingBuffer = Buffer.concat([incomingBuffer, data]);
                if (!sharedSecret) {
                    try {
                        const res = JSON.parse(incomingBuffer.toString());
                        currentServerId = res.pub;
                        
                        clear();
                        printHeader();
                        logger.important(`[MAST] Verified Sender ID: ${currentServerId.slice(0, 64)}...`, logger.colors.green);
                        
                        const signature = sign(res.nonce, clientKeys.privateKey).toString('hex');
                        sharedSecret = crypto.diffieHellman({
                            privateKey: clientXKeys.privateKey,
                            publicKey: crypto.createPublicKey(res.xpub)
                        });
                        logger.all(`[MAST] Session Fingerprint: ${getFingerprint(sharedSecret)}`);
                        socket.write(JSON.stringify({
                            pub: clientKeys.publicKey,
                            xpub: clientXKeys.publicKey.export({ type: 'spki', format: 'pem' }),
                            signature: signature
                        }));
                        incomingBuffer = Buffer.alloc(0);
                    } catch (e) {}
                    return;
                }
                while (incomingBuffer.length >= 4) {
                    const len = incomingBuffer.readUInt32BE(0);
                    if (incomingBuffer.length >= 4 + len) {
                        const dec = decrypt(incomingBuffer.slice(4, 4+len), sharedSecret);
                        const manifest = JSON.parse(dec.toString());
                        if (manifest.type === 'init') {
                            globalManifest = manifest;
                            stopThrobber();
                            resolve(manifest);
                        }
                        else if (manifest.type === 'merkle') {
                            const merkleFile = path.join(require('os').tmpdir(), `mast_merkle_${Date.now()}.json`);
                            fs.writeFileSync(merkleFile, JSON.stringify(manifest.merkle_tree));
                        }
                        else {
                            globalManifest = manifest;
                            stopThrobber();
                            handlePushUpdate(manifest);
                        }
                        incomingBuffer = incomingBuffer.slice(4 + len);
                    } else break;
                }
            });
        });
    }

    function truncatePath(p, limit = 40) {
        if (p.length <= limit) return p.padEnd(limit);
        const ext = path.extname(p);
        return (path.basename(p, ext).slice(0, limit-ext.length-3) + '...' + ext).padEnd(limit);
    }

    function printSecureHeader() {
        if (!currentServerId) return;
        clear();
        printHeader();
        logger.important(`[MAST] Verified Sender ID: ${currentServerId.slice(0, 64)}...`, logger.colors.green);
        if (sharedSecret) logger.all(`[MAST] Session Fingerprint: ${getFingerprint(sharedSecret)}`);
        console.log('--------------------------------------------------');
    }

    function handlePushUpdate(manifest) {
        printSecureHeader();
        logger.important('[MAST] Remote update pushed! New file list:', logger.colors.yellow);
        manifest.files.forEach((f, i) => console.log(`\x1b[33m[${i}]\x1b[0m ${truncatePath(f.path)} ${formatBytes(f.size)}`));
        process.stdout.write('\nEnter indices (0,1,2), range (0-5), or "all": ');
    }

    async function worker(manifest, queue, downloadDir, onProgress) {
        return new Promise((resolve) => {
            const socket = net.createConnection(manifest.data_port, HOST);
            let buf = Buffer.alloc(0);
            function next() {
                const id = queue.shift();
                if (id === undefined) return socket.end();
                const req = Buffer.alloc(36);
                req.write(manifest.session_id, 0, 32, 'hex');
                req.writeUInt32BE(id, 32);
                socket.write(req);
            }
            socket.on('connect', next);
            socket.on('data', (d) => {
                buf = Buffer.concat([buf, d]);
                if (buf.length >= 8) {
                    const cid = buf.readUInt32BE(0);
                    const len = buf.readUInt32BE(4);
                    if (buf.length >= 8 + len) {
                        const chunkData = decrypt(buf.slice(8, 8+len), sharedSecret);
                        
                        const chunkStart = cid * manifest.chunk_size;
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
                        
                        buf = buf.slice(8 + len);
                        onProgress();
                        next();
                    }
                }
            });
            socket.on('end', resolve);
        });
    }

    logger.important('[MAST] Initiating secure session...');
    await bootstrap();
    
    while (true) {
        clear();
        printSecureHeader();
        logger.important('--- Remote File Manifest ---', logger.colors.yellow);
        globalManifest.files.forEach((f, i) => console.log(`\x1b[33m[${i}]\x1b[0m ${truncatePath(f.path)} ${formatBytes(f.size)}`));
        
        const input = await ask('\nEnter indices (0,1,2), range (0-5), "all", or "q" to quit: ');
        if (input.toLowerCase() === 'q') process.exit(0);
        if (!input) continue;

        let selected = [];
        if (input.toLowerCase() === 'all') {
            selected = globalManifest.files;
        } else if (input.includes('-')) {
            const [startIdx, endIdx] = input.split('-').map(Number);
            selected = globalManifest.files.slice(startIdx, endIdx + 1);
        } else {
            selected = input.split(',').map(Number).filter(i => !isNaN(i) && globalManifest.files[i]).map(i => globalManifest.files[i]);
        }
        
        if (selected.length === 0) continue;
        
        const queue = [];
        selected.forEach(f => {
            for (let i = Math.floor(f.offset/globalManifest.chunk_size); i <= Math.floor((f.offset+f.size-1)/globalManifest.chunk_size); i++) {
                if (!queue.includes(i)) queue.push(i);
            }
        });

        const outDir = path.join(process.cwd(), 'downloads');
        if (!fs.existsSync(outDir)) fs.mkdirSync(outDir);
        selected.forEach(f => {
            const filePath = path.join(outDir, f.path);
            const fileDir = path.dirname(filePath);
            if (!fs.existsSync(fileDir)) fs.mkdirSync(fileDir, { recursive: true });
            const fd = fs.openSync(filePath, 'w');
            if (f.size > 0) {
                fs.writeSync(fd, Buffer.alloc(1), 0, 1, f.size - 1);
            }
            fs.closeSync(fd);
        });

        const streams = [];
        let completedChunks = 0;
        const totalChunks = queue.length;
        
        logger.important(`[MAST] Task: ${selected.length} files | ${totalChunks} chunks`);
        
        // Dynamic streams: scale up to MAX_STREAMS based on total chunks
        let optimalStreams = Math.min(MAX_STREAMS, Math.ceil(totalChunks / 20));
        if (optimalStreams < 4 && totalChunks > 1) optimalStreams = Math.min(totalChunks, 4);
        
        logger.all(`[MAST] Spawning ${optimalStreams} parallel data streams...`);
        
        lastSpeedUpdate = Date.now();
        lastCompleted = 0;
        currentMbps = 0;
        drawProgressBar(0, totalChunks, globalManifest.chunk_size);
        
        for (let i = 0; i < optimalStreams; i++) {
            streams.push(worker(globalManifest, queue, outDir, () => {
                completedChunks++;
                drawProgressBar(completedChunks, totalChunks, globalManifest.chunk_size);
            }));
        }
        await Promise.all(streams);
        
        console.log(); // new line after progress bar

        selected.forEach(f => {
            logger.important(`Saved: ${f.path}`);
        });
        
        await ask('\nPress Enter to continue downloading...');
    }
}

// --- INTERACTIVE WRAPPER ---
async function main() {
    if (command === 'serve' || command === 's') {
        const p = getArg('--path', '-p', process.argv[3]);
        const k = getArg('--key', '-k', process.argv[4]);
        const s = getArg('--streams', '-s', process.argv[5]);
        const P = getArg('--port', '-P', process.argv[6]);
        runServer(p, k, s, P);
    } else if (command === 'receive' || command === 'r') {
        const P = getArg('--port', '-P', process.argv[3]);
        const k = getArg('--key', '-k', process.argv[4]);
        const s = getArg('--streams', '-s', process.argv[5]);
        const H = getArg('--host', '-H', process.argv[6]);
        runClient(P, k, s, H);
    } else if (command === '--help' || command === '-h') {
        console.log("MAST Standalone\nUsage:\n  MAST serve [args]\n  MAST receive [args]\n  MAST (interactive)");
    } else {
        clear();
        console.log(`\n \x1b[35m[MAST]\x1b[0m\n`);
        const action = (await ask(' > (s)erve | (r)eceive: ')).toLowerCase();
        
        if (action === 's' || action === 'serve') {
            const p = await ask(' > Local Path: ') || './';
            const P = await ask(' > Port [3000]: ') || '3000';
            const s = await ask(' > Streams [4]: ') || '4';
            runServer(p, null, s, P);
        } else if (action === 'r' || action === 'receive') {
            const h = await ask(' > Remote Host [127.0.0.1]: ') || '127.0.0.1';
            const P = await ask(' > Remote Port [3000]: ') || '3000';
            const s = await ask(' > Parallel Streams [8]: ') || '8';
            runClient(P, null, s, h);
        } else {
            console.log(' ! Invalid command');
        }
    }
}

main();
