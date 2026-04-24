const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function getAllFiles(dirPath, arrayOfFiles) {
    const files = fs.readdirSync(dirPath);
    arrayOfFiles = arrayOfFiles || [];
    files.forEach(function(file) {
        if (fs.statSync(path.join(dirPath, file)).isDirectory()) {
            arrayOfFiles = getAllFiles(path.join(dirPath, file), arrayOfFiles);
        } else {
            arrayOfFiles.push(path.join(dirPath, file));
        }
    });
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
        const stats = fs.statSync(file);
        const relativePath = isDir ? path.relative(targetPath, file) : path.basename(file);
        manifestFiles.push({
            path: relativePath,
            size: stats.size,
            offset: totalSize,
            sha256: hashFile(file),
            absolutePath: file
        });
        totalSize += stats.size;
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
            
            const fd = fs.openSync(file.absolutePath, 'r');
            fs.readSync(fd, buffer, bytesRead, toReadInFile, readStartInFile);
            fs.closeSync(fd);
            
            bytesRead += toReadInFile;
            if (bytesRead >= bytesToRead) break;
        }
    }
    
    return buffer;
}

module.exports = { prepareDataset, readChunk };