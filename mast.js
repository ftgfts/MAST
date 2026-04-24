const { spawn } = require('child_process');
const fs = require('fs');
const logger = require('./lib/logger');
const { getOrGenerateKey } = require('./lib/auth');
const path = require('path');
const readline = require('readline');

const command = process.argv[2];

function ask(question) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => rl.question(question, answer => {
        rl.close();
        resolve(answer);
    }));
}

function clear() {
    process.stdout.write('\x1Bc');
}

function showHelp() {
    logger.important('\nCommands:');
    logger.all('  keys (k)    - Show your identities');
    logger.all('  serve (s)   - Start a server');
    logger.all('  receive (r) - Receive files');
    logger.all('  help (h)    - Show this help');
}

async function showWelcome() {
    clear();
    const serverId = getOrGenerateKey('server').publicKey;
    logger.important('--- MAST (Merkle Addressed Streaming Transfer) ---', logger.colors.magenta);
    logger.all(`Your ID: ${serverId.slice(0, 32)}...`);
    console.log('--------------------------------------------------');
}

async function interactive() {
    await showWelcome();
    const action = (await ask('Action: (s)erve, (r)eceive, (k)eys, (h)elp: ')).toLowerCase();
    
    if (action === '1' || action === 's' || action === 'serve') {
        const file = await ask('Path to file or folder: ');
        if (!file) return;
        clear();
        spawn('node', ['server.js', file], { stdio: 'inherit' });
    } else if (action === '2' || action === 'r' || action === 'receive') {
        const port = await ask('Server port (default 3000): ') || '3000';
        const addr = await ask('Server address (default 127.0.0.1): ') || '127.0.0.1';
        clear();
        spawn('node', ['client.js', port, 'none', '8', addr], { stdio: 'inherit' });
    } else if (action === 'k' || action === 'keys') {
        showKeys();
    } else {
        showHelp();
    }
}

function showKeys() {
    const s = getOrGenerateKey('server');
    const c = getOrGenerateKey('client');
    logger.important('\n--- Your Identities ---');
    logger.all(`Server ID: ${s.publicKey}`);
    logger.all(`Client ID: ${c.publicKey}`);
}

if (command === 'serve' || command === 's') {
    const p = process.argv[3];
    const cp = process.argv[4];
    spawn('node', ['server.js', p, cp], { stdio: 'inherit' });
} else if (command === 'receive' || command === 'r') {
    const addr = process.argv[3] || '127.0.0.1';
    const port = process.argv[4] || '3000';
    spawn('node', ['client.js', port, 'none', '8', addr], { stdio: 'inherit' });
} else if (command === 'keys' || command === 'k') {
    showKeys();
} else if (command === 'help' || command === 'h') {
    showHelp();
} else {
    interactive();
}