
# E2EE Chat App with X3DH

This project is a Python-based command-line prototype of a secure, end-to-end encrypted (E2EE) chat application. It implements the **X3DH (Extended Triple Diffie-Hellman)** key agreement protocol, which is the foundational technology used by secure messengers like Signal.

The system is split into two components:
1.  **`server.py`**: An untrusted server that relays public keys and encrypted messages.
2.  **`client.py`**: A client simulator that manages cryptographic keys, performs the E2EE handshake, and encrypts/decrypts messages.

At no point does the server have access to private keys or plaintext message content.

## Features Implemented

### 1. The Server (`server.py`)

The server is a simple Flask application that acts as an untrusted middleman. Its only jobs are to store public keys and relay encrypted messages.

* **/publish\_keys**: Receives and stores a user's public key "bundle" (Identity Key, Signed Pre-Key, and a list of One-Time Pre-Keys).
* **/get\_keys/&lt;username&gt;**: Provides a user's key bundle to another user who wants to start a chat. It automatically "pops" a One-Time Pre-Key from the list to ensure it's only used once.
* **/send**: Receives a fully encrypted JSON payload from a sender and saves it to a file-based mailbox for the intended recipient.
* **/receive/&lt;username&gt;**: Allows a user to retrieve all pending encrypted messages from their mailbox. The messages are deleted from the server after retrieval.

### 2. The Client (`client.py`)

The client handles all cryptographic operations, ensuring that all data leaving the device is already encrypted.

* **Key Generation**: Each client generates its own set of `x25519` keys required for X3DH:
    * A long-term **Identity Key**.
    * A medium-term **Signed Pre-Key**.
    * A list of disposable **One-Time Pre-Keys**.
* **Handshake Initiation (Alice's side)**: To start a chat, the client:
    1.  Fetches the recipient's (Bob's) key bundle from the server.
    2.  Generates a new temporary (ephemeral) key.
    3.  Performs the four X3DH Diffie-Hellman calculations.
    4.  Uses a Key Derivation Function (KDF) to combine the results into a single, shared secret session key.
* **Handshake Response (Bob's side)**: When receiving the *first* message from a new contact:
    1.  Uses the public keys included in the message (Alice's Identity and Ephemeral keys).
    2.  Performs the same four Diffie-Hellman calculations using its own private keys.
    3.  Arrives at the **identical** shared secret session key.
* **Secure Messaging**:
    * All messages are encrypted and decrypted locally using **AES-256-GCM**.
    * The first message sent to a user is a special "initial" message that includes the public keys needed to complete the handshake.

## Security Features

This implementation successfully achieves the core principles of a modern secure messenger:

* **End-to-End Encryption**: The server never sees plaintext data, only encrypted blobs.
* **Forward Secrecy**: Because the handshake relies on disposable one-time and ephemeral keys, a compromise of a user's long-term keys in the future **cannot** be used to decrypt past conversations.
* **Asynchronous Communication**: A user can initiate a secure chat and send messages to an offline recipient. The server will securely hold the keys and messages until the recipient logs on to retrieve them.
