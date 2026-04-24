# MAST: Merkle Addressed Streaming Transfer

MAST is a high-performance, secure file transfer protocol designed to thrive on high-latency overlay networks and standard clearnet links alike. By combining Merkle-tree content addressing with an 8-way parallel streaming engine, MAST bypasses the "sequential bottleneck" that plagues traditional TCP transfers over darknets like I2P and Tor.

## Key Features

- **Parallel Streaming Engine**: Utilizes multiple concurrent data streams to saturate available bandwidth regardless of network latency or RTT.
- **Merkle-Based Integrity**: Every data chunk is verified against a Merkle Root in real-time. If a single bit is corrupted, only the affected chunk is re-transmitted.
- **Secure by Design**: End-to-end encryption using X25519 key exchange and AES-256-GCM, with Ed25519 identities for persistent, trusted sessions.
- **Darknet Optimized**: Specific architectural considerations for I2P single-thread limits, Tor circuit jitter, and Yggdrasil IPv6 mesh routing.
- **Live Sync**: Native filesystem watching triggers encrypted manifest pushes to all active subscribers.

---

## How It Works

### Phase 1: Secure Bootstrap

The server and client perform a cryptographic handshake to verify identities (TOFU model) and derive a shared session secret. The server then sends a **Manifest** containing the file list and the **Merkle Root**.

### Phase 2: Parallel Data Pool

The client spawns multiple worker threads. Each thread connects to a randomized "Data Pool" port on the server and pulls unique chunks from a global queue.

- **Efficiency**: Instead of one pipe waiting for ACKs, 8+ pipes are constantly moving data.
- **Security**: Every chunk is independently encrypted for each session ID.

### Phase 3: Real-Time Validation

As chunks arrive, the client validates them against the Merkle tree.

- **Selective Repair**: If a chunk fails validation, the client issues a NACK for only that specific Chunk ID.
- **Zero Bloat**: Old manifests and trees are automatically purged from memory to prevent bloat during long-running sync sessions.

---

## Network Configuration

### Clearnet (Standard Internet)

The bootstrap server listens on port 3000 by default. Forward this port on your router to allow external connections.

### Yggdrasil / Mesh Networks

MAST binds to `::` (all interfaces), providing native support for IPv6 mesh networks. Simply provide the server's Yggdrasil IPv6 address to the client.

### Tor / I2P (Darknets)

Use a local tunnel manager (like `i2pd` or `tor`) to point an Onion or I2P address to the server's bootstrap port. MAST's parallel engine will automatically compensate for the high latency of these networks.

---

## Usage

### Interactive Mode

Run the wrapper to start an interactive session:

```bash
node mast.js
```

### Manual Mode

**Serve a folder:**

```bash
node server.js ./my_folder
```

**Receive files:**

```bash
node client.js 3000 none 8 127.0.0.1
```

---

## Security Audit

- **Handshake**: Ed25519 signatures verify that the sender owns their ID.
- **Session Keys**: X25519 Diffie-Hellman provides Perfect Forward Secrecy.
- **Fingerprinting**: A 16-character SHA-256 fingerprint is displayed to both parties for out-of-band verification.
- **Encryption**: AES-256-GCM ensures both confidentiality and data authenticity.
