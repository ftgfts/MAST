const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { buildMerkleTree, getRoot } = require('./lib/merkle');
const { prepareDataset } = require('./lib/files');
const { getOrGenerateKey, getXKey, sign, verify, encrypt, getFingerprint } = require('./lib/auth');
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

if (process.argv.includes('--help') || process.argv.includes('-h')) {
    console.log(`
MAST Server - Securely serve files and folders

Usage:
  node server.js [options] [path_to_folder]

Options:
  -p, --path <path>      Local directory to share (Default: ./)
  -k, --key <path>       Path to authorized client .pub key
  -s, --streams <num>    Number of parallel streams (Default: 4)
  -P, --port <num>       Port for bootstrap server (Default: 3000)
    `);
    process.exit(0);
}

const targetPath = getArg('--path', '-p', process.argv[2] || './');
const clientPubPath = getArg('--key', '-k', process.argv[3]);
const STREAM_COUNT = parseInt(getArg('--streams', '-s', process.argv[4] || 4));
const DEFAULT_BOOTSTRAP_PORT = parseInt(getArg('--port', '-P', process.argv[5] || 3000));

if (!fs.existsSync(targetPath)) {
    logger.error(`Target not found: ${targetPath}`);
    process.exit(1);
}

const serverKeys = getOrGenerateKey('server');
const serverXKeys = getXKey('server');
let authorizedClientPub = clientPubPath ? fs.readFileSync(clientPubPath, 'utf8') : null;

function signManifest(masterHash, files) {
    const payload = masterHash + files.map(f => f.path + ':' + (f.sha256 || '')).join('|');
    return sign(payload, serverKeys.privateKey).toString('hex');
}

async function initServer() {
    clear();
    console.log(`\x1b[35m           
 _____ _____ _____ _____ 
|     |  _  |   __|_   _|
| | | |     |__   | | |  
|_|_|_|__|__|_____| |_|  
\x1b[0m`);
    logger.important('--------------------------------------------------');
    logger.important(`[MAST] Initialized ID: ${serverKeys.publicKey.slice(0, 64)}...`);

    startThrobber('[MAST] Preparing dataset and building Merkle tree...');
    let dataset = prepareDataset(targetPath);
    let tree = await buildMerkleTree(dataset);
    let masterHash = getRoot(tree).toString('hex');
    stopThrobber();

    const activeSessions = new Map();
    const subscribers = new Set();
    let datasetVersion = 1;

    logger.important(`[MAST] Ready: ${dataset.manifestFiles.length} files | ${dataset.chunkCount} chunks | ${formatBytes(dataset.totalSize)}`, logger.colors.green);

    async function broadcastUpdate() {
        stopThrobber();
        logger.important('[MAST] Change detected! Rebuilding and pushing update...', logger.colors.yellow);
        startThrobber('[MAST] Rebuilding dataset and Merkle tree...');
        dataset = prepareDataset(targetPath);
        tree = await buildMerkleTree(dataset);
        masterHash = getRoot(tree).toString('hex');
        datasetVersion++;
        for (const [sessionId, session] of activeSessions.entries()) {
            session.version = datasetVersion;
        }
        stopThrobber();
        const manifest = {
            type: 'update',
            total_size: dataset.totalSize,
            chunk_count: dataset.chunkCount,
            chunk_size: dataset.CHUNK_SIZE,
            master_hash: masterHash,
            manifest_sig: signManifest(masterHash, dataset.manifestFiles),
            files: dataset.manifestFiles
        };
        for (const sub of subscribers) {
            try {
                const encrypted = encrypt(Buffer.from(JSON.stringify(manifest)), sub.secret);
                const packet = Buffer.alloc(4);
                packet.writeUInt32BE(encrypted.length, 0);
                sub.socket.write(packet);
                sub.socket.write(encrypted);
            } catch (e) {
                subscribers.delete(sub);
            }
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
        socket.on('error', () => {}); 
        socket.on('data', (data) => {
            if (data.length < 36) return;
            const sessionId = data.slice(0, 32).toString('hex');
            const chunkId = data.readUInt32BE(32);
            const session = activeSessions.get(sessionId);
            if (!session) return;
            if (session.version !== datasetVersion) {
                logger.all(`[MAST] Rejecting stale chunk request from old dataset version`);
                return;
            }
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
            socket.on('error', () => {
                for (const sub of subscribers) {
                    if (sub.socket === socket) {
                        subscribers.delete(sub);
                        break;
                    }
                }
            });
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
                    const clientPub = res.pub;
                    const clientXPubPem = res.xpub;
                    const signature = Buffer.from(res.signature, 'hex');
                    if (authorizedClientPub && clientPub !== authorizedClientPub) {
                        socket.end();
                        return;
                    }
                    if (!verify(nonce.toString('hex'), signature, clientPub)) {
                        socket.end();
                        return;
                    }
                    const clientXPub = crypto.createPublicKey(clientXPubPem);
                    const secret = crypto.diffieHellman({
                        privateKey: serverXKeys.privateKey,
                        publicKey: clientXPub
                    });
                    const sessionId = crypto.randomBytes(32).toString('hex');
                    activeSessions.set(sessionId, { secret, clientPub, version: datasetVersion });
                    const fingerprint = getFingerprint(secret);
                    logger.important(`[MAST] Secure handshake with client [${clientPub.slice(0, 16)}...]`, logger.colors.green);
                    logger.all(`[MAST] Session Fingerprint: ${fingerprint}`);
                    const manifest = {
                        type: 'init',
                        session_id: sessionId,
                        total_size: dataset.totalSize,
                        chunk_count: dataset.chunkCount,
                        chunk_size: dataset.CHUNK_SIZE,
                        stream_count: STREAM_COUNT,
                        data_port: dataPort,
                        master_hash: masterHash,
                        manifest_sig: signManifest(masterHash, dataset.manifestFiles),
                        files: dataset.manifestFiles
                    };
                    const encryptedManifest = encrypt(Buffer.from(JSON.stringify(manifest)), secret);
                    const packet = Buffer.alloc(4);
                    packet.writeUInt32BE(encryptedManifest.length, 0); 
                    socket.write(packet);
                    socket.write(encryptedManifest);
                    
                    const merkleData = {
                        type: 'merkle',
                        merkle_tree: tree.map(level => level.map(node => node.toString('hex')))
                    };
                    const encMerkle = encrypt(Buffer.from(JSON.stringify(merkleData)), secret);
                    const merklePkt = Buffer.alloc(4);
                    merklePkt.writeUInt32BE(encMerkle.length, 0);
                    socket.write(merklePkt);
                    socket.write(encMerkle);

                    subscribers.add({ socket, secret });
                } catch (e) {}
            });
        });
        bootstrapServer.listen(DEFAULT_BOOTSTRAP_PORT, '::', () => {
            logger.important(`[MAST] Bootstrap listening on [::]:${DEFAULT_BOOTSTRAP_PORT}`);
        });
    });
}

initServer().catch(err => {
    console.error('Server failed to start:', err);
});