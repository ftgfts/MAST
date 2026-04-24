const fs = require('fs');
const path = require('path');

const CONFIG_PATH = path.join(__dirname, '..', 'mast.config.json');
let config = { log_level: 'IMPORTANT', log_file: 'mast.log' };
try {
    config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
} catch (e) {}

const LEVELS = {
    'ALL': 0,
    'IMPORTANT': 1,
    'ERROR': 2
};

const currentLevel = LEVELS[config.log_level] !== undefined ? LEVELS[config.log_level] : 1;
const logPath = path.resolve(__dirname, '..', config.log_file);

function log(msg, level = 'ALL', color = '') {
    const timestamp = new Date().toISOString();
    const cleanMsg = `[${timestamp}] [${level}] ${msg}`;
    try {
        fs.appendFileSync(logPath, cleanMsg + '\n');
    } catch (e) {}
    if (LEVELS[level] >= currentLevel) {
        if (color) {
            console.log(color + '%s\x1b[0m', msg);
        } else {
            console.log(msg);
        }
    }
}

const colors = {
    cyan: '\x1b[36m',
    yellow: '\x1b[33m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    dim: '\x1b[90m',
    magenta: '\x1b[35m'
};

module.exports = {
    all: (msg) => log(msg, 'ALL'),
    important: (msg, color = colors.cyan) => log(msg, 'IMPORTANT', color),
    error: (msg) => log(msg, 'ERROR', colors.red),
    colors,
    config
};
