const crypto = require('crypto');
const { readChunk } = require('./files');

function hash(data) {
    return crypto.createHash('sha256').update(data).digest();
}

async function buildMerkleTree(dataset) {
    if (!dataset || dataset.chunkCount === 0) return [[]];
    
    let nodes = [];
    for (let i = 0; i < dataset.chunkCount; i++) {
        nodes.push(hash(readChunk(dataset, i)));
        
        if (i % 50 === 0) {
            await new Promise(resolve => setImmediate(resolve));
        }
    }
    
    let tree = [nodes];
    while (nodes.length > 1) {
        let nextLevel = [];
        for (let i = 0; i < nodes.length; i += 2) {
            if (i + 1 < nodes.length) {
                nextLevel.push(hash(Buffer.concat([nodes[i], nodes[i + 1]])));
            } else {
                nextLevel.push(nodes[i]);
            }
        }
        nodes = nextLevel;
        tree.push(nodes);
        await new Promise(resolve => setImmediate(resolve));
    }
    return tree;
}

function getRoot(tree) {
    if (!tree || tree.length === 0 || tree[0].length === 0) return Buffer.from([]);
    return tree[tree.length - 1][0];
}

function getProof(tree, index) {
    const proof = [];
    for (let i = 0; i < tree.length - 1; i++) {
        const level = tree[i];
        const isRight = index % 2 === 1;
        const siblingIdx = isRight ? index - 1 : index + 1;
        if (siblingIdx < level.length) {
            proof.push({ hash: level[siblingIdx], position: isRight ? 'left' : 'right' });
        }
        index = Math.floor(index / 2);
    }
    return proof;
}

function verifyProof(chunkHash, proof, root) {
    let currentHash = chunkHash;
    for (const p of proof) {
        const buffers = p.position === 'left' ? [p.hash, currentHash] : [currentHash, p.hash];
        currentHash = hash(Buffer.concat(buffers));
    }
    return currentHash.equals(root);
}

module.exports = { hash, buildMerkleTree, getRoot, getProof, verifyProof };
