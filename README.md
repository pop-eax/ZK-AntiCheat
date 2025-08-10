# Zero-Knowledge Anti-Cheat Software

A proof-of-concept system that uses cryptographic proofs to verify fair gameplay and detect cheating in video game speedrunning.

## 🎯 Project Overview

ZK-AntiCheat demonstrates how zero-knowledge proofs can be used to create tamper-proof anti-cheat systems that:
- Monitor game memory states cryptographically
- Generate proofs of fair gameplay
- Detect unauthorized memory modifications
- Maintain player privacy through ZK proofs

## 🏗️ Architecture

The project consists of three main components:

### 1. **Client** (`client/`)
- **Language**: Rust
- **Purpose**: Memory monitoring and state capture
- **Features**:
  - Process memory dumping and analysis
  - Merkle tree generation from memory chunks
  - Static vs. dynamic memory region profiling
  - Continuous state monitoring

### 2. **Server Prover** (`serverProver/`)
- **Language**: TypeScript (Node.js)
- **Purpose**: ZK proof generation and verification
- **Features**:
  - Noir.js circuit execution
  - Barretenberg backend integration
  - Recursive proof aggregation
  - Whitelist validation

### 3. **Circuits** (`circuits/`)
- **Language**: Noir
- **Purpose**: ZK circuit definitions
- **Components**:
  - `gamePlayProver`: Recursive proof aggregation
  - `merkleProof`: Memory integrity verification
  - `stateTransition`: State machine validation
  - `whitelist`: Memory region validation

## 🚀 Quick Start

### Prerequisites
- Rust 1.70+
- Node.js 18+
- Bun (for serverProver)
- Nargo (for circuit compilation)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd fairfy
   ```

2. **Setup Client**
   ```bash
   cd client
   cargo build
   ```

3. **Setup Server Prover**
   ```bash
   cd ../serverProver
   bun install
   ```

4. **Compile Circuits**
   ```bash
   cd ../circuits
   # Compile each circuit individually
   cd gamePlayProver && nargo compile
   cd ../merkleProof && nargo compile
   cd ../stateTransition && nargo compile
   cd ../whitelist && nargo compile
   cd ../recursiveWhitelist && nargo compile
   ```

### Running the System

1. **Start the ZK Prover Server**
   ```bash
   cd serverProver
   bun run
   ```

2. **Run the Memory Monitor Client**
   ```bash
   cd client
   cargo run
   ```

## 📊 API Endpoints

### Server Prover (`:9000`)
- `POST /` - Submit game state for proof generation
- `GET /health` - Health check and status


## 🔧 Configuration

### Environment Variables
- `PORT` - Server port (default: 9000)
- `HOST` - Server host (default: 0.0.0.0)

### Memory Monitoring
- `CHUNK_SIZE` - Memory chunk size for hashing (default: 2048)
- `PATH_LENGTH` - Merkle tree path length (default: 64)
- `MEMORY_DUMP_INTERVAL_SECONDS` - Monitoring interval (default: 40)

## 🧪 Testing

### Run Tests
```bash
# Client tests
cd client && cargo test

# Server tests
cd server && cargo test

# TypeScript compilation check
cd serverProver && npx tsc --noEmit
```
## 🚨 Security Notes

⚠️ **This is a proof-of-concept implementation with known security vulnerabilities:**

- No input validation or sanitization
- Hardcoded cryptographic values
- No authentication or authorization
- Memory safety concerns
- No rate limiting

5. Submit a pull request


## 🙏 Acknowledgments

- [Noir](https://noir-lang.org/) - ZK programming language
- [FCEUX](https://fceux.com/web/home.html) - FCEUX