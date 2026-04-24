const fs = require('fs');
const path = require('path');

function getAllFiles(dirPath, arrayOfFiles) {
    const files = fs.readdirSync(dirPath);
    arrayOfFiles = arrayOfFiles || [];
    files.forEach(function(file) {
        if (fs.statSync(dirPath + "/" + file).isDirectory()) {
            arrayOfFiles = getAllFiles(dirPath + "/" + file, arrayOfFiles);
        } else {
            arrayOfFiles.push(path.join(dirPath, "/", file));
        }
    });
    return arrayOfFiles;
}

function prepareDataset(targetPath) {
    const isDir = fs.statSync(targetPath).isDirectory();
    const files = isDir ? getAllFiles(targetPath) : [targetPath];
    let totalSize = 0;
    const manifestFiles = [];
    const buffers = [];
    files.forEach(file => {
        const stats = fs.statSync(file);
        const relativePath = isDir ? path.relative(targetPath, file) : path.basename(file);
        manifestFiles.push({
            path: relativePath,
            size: stats.size,
            offset: totalSize
        });
        totalSize += stats.size;
        buffers.push(fs.readFileSync(file));
    });
    const fullBuffer = Buffer.concat(buffers);
    const chunks = [];
    const CHUNK_SIZE = 64 * 1024;
    for (let i = 0; i < fullBuffer.length; i += CHUNK_SIZE) {
        chunks.push(fullBuffer.slice(i, i + CHUNK_SIZE));
    }
    return {
        fullBuffer,
        chunks,
        manifestFiles
    };
}

module.exports = { prepareDataset };
