const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const logger = require('./logger');

const CONFIG_PATH = path.join(__dirname, '..', 'mast.config.json');
let config = { identities_dir: './identities' };
try {
    config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
} catch (e) {}

const ID_DIR = path.resolve(config.identities_dir);
if (!fs.existsSync(ID_DIR)) fs.mkdirSync(ID_DIR, { recursive: true });

function getOrGenerateKey(name) {
    const keyPath = path.join(ID_DIR, `${name}.key`);
    const pubPath = path.join(ID_DIR, `${name}.pub`);

    if (fs.existsSync(keyPath)) {
        let content = fs.readFileSync(keyPath, 'utf8').trim();
        let privateKey;
        try {
            if (content.length === 64 && /^[0-9a-fA-F]+$/.test(content)) {
                const { privateKey: pk } = crypto.generateKeyPairSync('ed25519');
                privateKey = pk;
                fs.writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
            } else {
                privateKey = crypto.createPrivateKey(content);
            }
        } catch (e) {
            const pair = crypto.generateKeyPairSync('ed25519');
            privateKey = pair.privateKey;
            fs.writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
        }
        const publicKey = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('hex');
        if (!fs.existsSync(pubPath)) fs.writeFileSync(pubPath, publicKey);
        return { privateKey, publicKey };
    }

    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    const pubHex = publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
    fs.writeFileSync(keyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
    fs.writeFileSync(pubPath, pubHex);
    return { privateKey, publicKey: pubHex };
}

function getXKey(name) {
    const xKeyPath = path.join(ID_DIR, `${name}.xkey`);
    if (fs.existsSync(xKeyPath)) {
        const pem = fs.readFileSync(xKeyPath, 'utf8');
        const privateKey = crypto.createPrivateKey(pem);
        const publicKey = crypto.createPublicKey(privateKey);
        return { privateKey, publicKey };
    }
    const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
    fs.writeFileSync(xKeyPath, privateKey.export({ type: 'pkcs8', format: 'pem' }));
    return { privateKey, publicKey };
}

function sign(data, privateKey) {
    return crypto.sign(null, Buffer.from(data), privateKey);
}

function verify(data, signature, publicKeyHex) {
    try {
        const publicKey = crypto.createPublicKey({
            key: Buffer.from(publicKeyHex, 'hex'),
            format: 'der',
            type: 'spki'
        });
        return crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(signature, 'hex'));
    } catch (e) {
        return false;
    }
}

function encrypt(data, secret) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', secret.slice(0, 32), iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, encrypted]);
}

function decrypt(data, secret) {
    const iv = data.slice(0, 12);
    const tag = data.slice(12, 28);
    const encrypted = data.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', secret.slice(0, 32), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

function getFingerprint(secret) {
    return crypto.createHash('sha256').update(secret).digest('hex').slice(0, 16);
}

module.exports = { getOrGenerateKey, getXKey, sign, verify, encrypt, decrypt, getFingerprint };

