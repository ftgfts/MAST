const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const fdCache = new Map();
function getCachedFd(filePath) {
    if (fdCache.has(filePath)) return fdCache.get(filePath);
    try {
        const fd = fs.openSync(filePath, 'r');
        fdCache.set(filePath, fd);
        return fd;
    } catch (e) {
        return null;
    }
}

function getAllFiles(dirPath, arrayOfFiles) {
    arrayOfFiles = arrayOfFiles || [];
    try {
        const files = fs.readdirSync(dirPath);
        files.forEach(function (file) {
            if (file.startsWith('.')) return;

            try {
                if (fs.statSync(path.join(dirPath, file)).isDirectory()) {
                    arrayOfFiles = getAllFiles(path.join(dirPath, file), arrayOfFiles);
                } else {
                    arrayOfFiles.push(path.join(dirPath, file));
                }
            } catch (e) {
            }
        });
    } catch (e) {
    }
    return arrayOfFiles;
}

function hashFile(filePath) {
    try {
        const data = fs.readFileSync(filePath);
        return crypto.createHash('sha256').update(data).digest('hex');
    } catch (e) {
        return null;
    }
}

function prepareDataset(targetPath) {
    let files = [];
    let isDir = false;
    if (fs.existsSync(targetPath)) {
        isDir = fs.statSync(targetPath).isDirectory();
        files = isDir ? getAllFiles(targetPath) : [targetPath];
    }
    
    let totalSize = 0;
    const manifestFiles = [];
    
    files.forEach(file => {
        try {
            const stats = fs.statSync(file);
            const relativePath = isDir ? path.relative(targetPath, file) : path.basename(file);
            
            const pathSegments = relativePath.split(/[\\\/]/);
            if (pathSegments.some(segment => segment.startsWith('.'))) {
                return;
            }
            
            manifestFiles.push({
                path: relativePath.replace(/\\/g, '/'),
                size: stats.size,
                offset: totalSize,
                sha256: hashFile(file),
                absolutePath: file
            });
            totalSize += stats.size;
        } catch (e) {
        }
    });

    let CHUNK_SIZE = 64 * 1024;
    if (totalSize > 100 * 1024 * 1024) CHUNK_SIZE = 256 * 1024;
    if (totalSize > 1024 * 1024 * 1024) CHUNK_SIZE = 1 * 1024 * 1024;
    if (totalSize > 10 * 1024 * 1024 * 1024) CHUNK_SIZE = 10 * 1024 * 1024;
    if (totalSize > 100 * 1024 * 1024 * 1024) CHUNK_SIZE = 50 * 1024 * 1024;

    const chunkCount = Math.ceil(totalSize / CHUNK_SIZE);
    
    return {
        totalSize,
        chunkCount,
        manifestFiles,
        CHUNK_SIZE,
        targetPath
    };
}

function readChunk(dataset, chunkId) {
    const chunkStart = chunkId * dataset.CHUNK_SIZE;
    const chunkEnd = chunkStart + dataset.CHUNK_SIZE;
    let bytesToRead = dataset.CHUNK_SIZE;
    if (chunkStart >= dataset.totalSize) return Buffer.alloc(0);
    if (chunkEnd > dataset.totalSize) bytesToRead = dataset.totalSize - chunkStart;

    const buffer = Buffer.alloc(bytesToRead);
    let bytesRead = 0;

    for (const file of dataset.manifestFiles) {
        const fileStart = file.offset;
        const fileEnd = file.offset + file.size;

        if (chunkStart + bytesRead < fileEnd && chunkStart + bytesRead >= fileStart) {
            const readStartInFile = (chunkStart + bytesRead) - fileStart;
            const toReadInFile = Math.min(fileEnd - (chunkStart + bytesRead), bytesToRead - bytesRead);

            const fd = getCachedFd(file.absolutePath);
            if (fd !== null) {
                fs.readSync(fd, buffer, bytesRead, toReadInFile, readStartInFile);
            }

            bytesRead += toReadInFile;
            if (bytesRead >= bytesToRead) break;
        }
    }

    return buffer;
}

function clearFdCache() {
    for (const [filePath, fd] of fdCache.entries()) {
        try { fs.closeSync(fd); } catch (e) { }
    }
    fdCache.clear();
}

module.exports = { prepareDataset, readChunk, clearFdCache };