# PQC + Homomorphic Encryption Secure Chat

A Python-based secure messaging prototype that combines:
- Post-Quantum Cryptography (PQC) using ML-KEM-1024 (Kyber) for key exchange.
- AES-256-GCM for end-to-end content encryption.
- A DRM layer with play-limit enforcement (simple server-side counter, optional HE flow).
- An interactive terminal UI for sending/receiving messages.

The server is untrusted: it never sees plaintext or private keys, and messages are auto-deleted after delivery.

---

## Repository structure

PQC-HOMOMORPHIC-ENCRYPTION-INDUSTRY-PROJECT/
├── previous client.py files/
│ ├── client_pqc_drm.py
│ ├── client_pqc.py
│ └── client.py
├── server_messages/
│ ├── alice/ # runtime mailbox (auto-created)
│ └── bob/ # runtime mailbox (auto-created)
├── test files/
│ ├── test_HE.py
│ ├── test_pqc_Pure.py
│ └── test_pqc.py
├── venv/ # local virtual environment (optional)
├── client_interactive.py # interactive PQC+DRM client (recommended)
├── drm_policy.py # HE DRM utilities (optional HE flow)
├── README.md
├── requirements.txt
└── server.py # untrusted relay server (auto-deletes after read)

text

---

## Features

- Quantum-safe session setup with ML-KEM-1024 (Kyber).
- End-to-end encryption with AES-256-GCM.
- Optional DRM play-limit per message.
- Auto-delete messages after retrieval to prevent replays and decryption errors.
- Rich interactive CLI for a smoother UX.

---

## Quick start

1) Create and activate a virtual environment

python -m venv venv

Windows
venv\Scripts\activate

macOS/Linux
source venv/bin/activate

text

2) Install dependencies

pip install -r requirements.txt

text

3) Start the server

python server.py

text

4) Run the interactive client in two terminals

Terminal A:
python client_interactive.py

enter username: alice
text

Terminal B:
python client_interactive.py

enter username: bob
text

5) In Alice’s UI
- Choose “Send Message”
- Recipient: bob
- Enter message text
- Enable DRM: yes/no
- If yes, set “Maximum plays” (e.g., 3)

6) In Bob’s UI
- Choose “Check Inbox”
- If DRM enabled, you’ll see “DRM: Play X/Y” until limit is reached.
- After delivery, messages are removed from the server to avoid re-decryption errors.

---

## How it works

- Key exchange: The client publishes an ML-KEM public key. The sender encapsulates a shared secret to the recipient’s public key; the recipient decapsulates it to derive the same secret. That secret (or a KDF-derived 32 bytes) is used as the AES-256-GCM key.
- Messaging: Each message is encrypted locally (nonce + ciphertext) and posted to the server. The server just relays and stores encrypted blobs temporarily.
- DRM (default simple mode): The server tracks a per-message play counter and enforces a maximum number of allowed decryptions. The optional HE flow in `drm_policy.py` demonstrates homomorphic counter increments without revealing the raw count.

---

## Commands and utilities

- Test PQC (ML-KEM) flow:
python test files/test_pqc_Pure.py

text

- Test homomorphic encryption utilities:
python test files/test_HE.py
python drm_policy.py

text

- Check server status (in browser):
http://127.0.0.1:5000/status

text

- Clear a user’s inbox (debug):
DELETE /clear_inbox/<username>

text

---

## Configuration notes

- Requirements (see requirements.txt):
  - flask
  - cryptography
  - pqcrypto (ML-KEM-1024)
  - requests
  - numpy
  - tenseal (optional HE flow)
  - rich (UI)

- Messages are persisted under `server_messages/<user>/` while pending, then deleted on delivery.

---

## Security model

- End-to-end encryption: Server never sees plaintext or private keys.
- Post-quantum resilience: ML-KEM-1024 protects key establishment from quantum attacks.
- Forward secrecy: Fresh encapsulations per session reduce cross-message risk.
- Replay mitigation: Auto-delete after delivery and session key separation.
- DRM: Play-limit tracking enforced without exposing plaintext content.

Note: This is a research prototype. For production, add TLS, authenticated users, key rotation, rate limiting, database storage, and auditing.

---

## Troubleshooting

- “Decryption failed” when re-checking old messages:
  - The server now auto-deletes messages after delivery. If you were running an older server, clear `server_messages/` and restart.
- TenSEAL import errors:
  - Ensure `numpy` is installed before `tenseal`. Try `pip install numpy tenseal`.
- pqcrypto import errors:
  - Use ML-KEM module path: `from pqcrypto.kem.ml_kem_1024 import generate_keypair, encrypt, decrypt`.

---

## Roadmap

- Optional: switch DRM counter to full HE flow (encrypted counters persisted and updated homomorphically).
- Add authenticated metadata (AAD) and HKDF on KEM secrets.
- Persistent DB backend (SQLite/PostgreSQL).
- Web or mobile client front-ends.

---

## License

MIT — see LICENSE.

---

## Acknowledgments

- NIST PQC (ML-KEM / Kyber)
- OpenMined TenSEAL
- cryptography.io
- Textualize Rich