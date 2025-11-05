
# 🔐 PQC + Homomorphic Encryption Chat System

A Python-based secure messaging prototype implementing **Post-Quantum Cryptography (PQC)** and **Homomorphic Encryption (HE)** for quantum-resistant end-to-end encryption with built-in DRM enforcement.

This project demonstrates the integration of:
- **ML-KEM-1024 (Kyber)** - NIST-standardized post-quantum key encapsulation
- **AES-256-GCM** - Authenticated symmetric encryption
- **TenSEAL** - Homomorphic encryption for privacy-preserving DRM
- **Interactive CLI** - Rich terminal UI for user-friendly messaging

---

## 🎯 Project Overview

The system consists of three main components:

1. **`server.py`** - Untrusted relay server for keys and encrypted messages
2. **`client_interactive.py`** - Interactive client with quantum-safe E2EE
3. **`drm_policy.py`** - Homomorphic encryption DRM enforcement module

**Key Innovation**: Server can enforce DRM policies (play count limits) without ever decrypting message content or knowing actual usage statistics.

---

## 🛡️ Security Architecture

### Post-Quantum Key Exchange (ML-KEM-1024)

Replaces classical Diffie-Hellman (x25519) with **NIST-standardized ML-KEM** (Module Lattice Key Encapsulation Mechanism), protecting against:
- **Shor's Algorithm** - Quantum attacks on RSA/ECC
- **Harvest-now-decrypt-later** attacks

**How it works:**
1. Alice fetches Bob's ML-KEM public key from server
2. Alice encapsulates a shared secret → generates ciphertext
3. Bob decapsulates ciphertext with his private key → recovers same secret
4. Both derive AES-256-GCM session key from shared secret

### End-to-End Encryption

- **Content encryption**: AES-256-GCM (authenticated encryption)
- **Session establishment**: ML-KEM-1024 key encapsulation
- **Forward secrecy**: Fresh session keys per conversation
- **Server trust model**: Zero-knowledge relay (never sees plaintext)

### Homomorphic DRM Enforcement

Uses **TenSEAL (BFV scheme)** to enable server-side policy enforcement without revealing usage data:

- Play counters encrypted with homomorphic encryption
- Server increments counters **without decryption**
- Only client (with secret key) can verify actual count
- Enforces limits while preserving user privacy

---

## 📋 Features Implemented

### Server (`server.py`)

| Endpoint | Purpose | Security |
|----------|---------|----------|
| `/publish_keys` | Store user's ML-KEM public key | Public key storage only |
| `/get_keys/<user>` | Retrieve public key for session init | No private data exposed |
| `/send` | Store encrypted message | Content remains encrypted |
| `/receive/<user>` | Deliver pending messages | Auto-delete after reading |
| `/drm_play` | Increment play counter | Server-side DRM tracking |
| `/drm_status` | Check DRM limit status | Returns counter state |

**Key Properties:**
- ✅ Never stores private keys
- ✅ Never decrypts message content
- ✅ Auto-deletes messages after delivery
- ✅ Tracks DRM compliance without seeing usage data

### Interactive Client (`client_interactive.py`)

**Quantum-Safe Operations:**
- **Key Generation**: ML-KEM-1024 keypair creation
- **Session Establishment**: Quantum-resistant key agreement
- **Message Encryption**: AES-256-GCM with PQC-derived keys
- **DRM Token Creation**: Homomorphically encrypted play counters

**User Interface:**
- 📨 Send encrypted messages with optional DRM
- 📬 Check inbox and decrypt messages
- 👥 View active secure sessions
- 🎫 Configure DRM play limits per message
- 🚪 Clean exit with session cleanup

### DRM Policy Module (`drm_policy.py`)

**Homomorphic Encryption Features:**
- Initialize TenSEAL BFV context for integer operations
- Create DRM licenses with encrypted play counters
- Homomorphically increment counters (server-side)
- Decrypt and verify limits (client-side only)

**Privacy Guarantee**: Server performs arithmetic on encrypted values without learning actual counts.

---

## 🚀 Installation

### Prerequisites

- Python 3.8+
- pip package manager
- Virtual environment (recommended)

### Setup

