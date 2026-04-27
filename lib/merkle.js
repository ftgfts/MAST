const crypto = require('crypto');
const { readChunk } = require('./files');

function hash(data) {
    return crypto.createHash('sha256').update(data).digest();
}

async function buildMerkleTree(dataset) {
    if (!dataset || dataset.chunkCount === 0) return [[]];

    const nodes = [];
    
    async function readLeaves(i) {
        if (i >= dataset.chunkCount) return;
        
        nodes.push(hash(readChunk(dataset, i)));
        
        if (i % 50 === 0) {
            await new Promise(resolve => setTimeout(resolve, 0));
        }
        
        return readLeaves(i + 1);
    }
    
    await readLeaves(0);

    async function buildTreeLevels(currentLevel, tree = []) {
        tree.push(currentLevel);
        if (currentLevel.length <= 1) return tree;

        const nextLevel = [];
        
        async function processPairs(i) {
            if (i >= currentLevel.length) return;
            
            if (i + 1 < currentLevel.length) {
                nextLevel.push(hash(Buffer.concat([currentLevel[i], currentLevel[i + 1]])));
            } else {
                nextLevel.push(currentLevel[i]);
            }
            
            if (i % 50 === 0) {
                await new Promise(resolve => setTimeout(resolve, 0));
            }
            
            return processPairs(i + 2);
        }
        
        await processPairs(0);
        return buildTreeLevels(nextLevel, tree);
    }

    return buildTreeLevels(nodes);
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
