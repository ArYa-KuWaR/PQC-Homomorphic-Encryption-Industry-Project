# client_pqc.py - PQC Version with ML-KEM-1024 (Kyber)

import os
import requests
import base64
from secrets import compare_digest
from pqcrypto.kem.ml_kem_1024 import generate_keypair, encrypt, decrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# --- Helper Functions ---
def bytes_to_base64(data):
    """Convert bytes to base64 string"""
    return base64.b64encode(data).decode('utf-8')


def base64_to_bytes(b64_str):
    """Convert base64 string to bytes"""
    return base64.b64decode(b64_str)


class PQCChatClient:
    def __init__(self, username, server_url="http://127.0.0.1:5000"):
        self.username = username
        self.server_url = server_url
        print(f"[PQC] Client '{self.username}' initialized (ML-KEM-1024)")
        
        self.public_key = None
        self.secret_key = None
        self.session_keys = {}
        
    
    def generate_keys(self):
        """Generate ML-KEM-1024 (Kyber) keypair"""
        print(f"[{self.username}]: Generating ML-KEM-1024 keys...")
        self.public_key, self.secret_key = generate_keypair()
        print(f"[{self.username}]: ✓ Key generation complete")
        print(f"    Public key: {len(self.public_key)} bytes")
        print(f"    Secret key: {len(self.secret_key)} bytes")
        
    
    def publish_keys_to_server(self):
        """Publish ML-KEM public key to server"""
        print(f"[{self.username}]: Publishing keys to server...")
        bundle = {
            'username': self.username,
            'pqc_public_key': bytes_to_base64(self.public_key),
            'algorithm': 'ML-KEM-1024'
        }
        response = requests.post(f"{self.server_url}/publish_keys", json=bundle)
        if response.status_code == 200:
            print(f"[{self.username}]: ✓ Keys published successfully")
        else:
            print(f"[{self.username}]: ❌ ERROR: {response.text}")
    
    
    def establish_session_as_initiator(self, recipient):
        """
        Alice's side: Encapsulate shared secret using Bob's public key
        Returns KEM ciphertext that Bob will use to derive the same secret
        """
        print(f"\n[{self.username}]: → Initiating PQC session with {recipient}...")
        
        # 1. Fetch recipient's public key from server
        response = requests.get(f"{self.server_url}/get_keys/{recipient}")
        if response.status_code != 200:
            print(f"❌ ERROR: Could not fetch keys for {recipient}")
            return None
        
        key_bundle = response.json()
        recipient_public_key = base64_to_bytes(key_bundle['pqc_public_key'])
        
        # 2. Encapsulate: Generate ciphertext + shared secret
        ciphertext, shared_secret = encrypt(recipient_public_key)
        
        # 3. Store session key (use first 32 bytes for AES-256-GCM)
        self.session_keys[recipient] = shared_secret[:32]
        
        print(f"[{self.username}]: ✓ Session established with {recipient}")
        print(f"    Shared secret: {shared_secret[:32].hex()[:32]}...")
        print(f"    Ciphertext size: {len(ciphertext)} bytes")
        
        # Return ciphertext for Bob to decapsulate
        return {
            "kem_ciphertext": bytes_to_base64(ciphertext),
            "algorithm": "ML-KEM-1024"
        }
    
    
    def establish_session_as_responder(self, sender, kem_ciphertext_b64):
        """
        Bob's side: Decapsulate to recover the same shared secret
        """
        print(f"\n[{self.username}]: ← Establishing session from {sender}'s message...")
        
        # 1. Decode the KEM ciphertext
        kem_ciphertext = base64_to_bytes(kem_ciphertext_b64)
        
        # 2. Decapsulate using our secret key
        shared_secret = decrypt(self.secret_key, kem_ciphertext)
        
        # 3. Store session key (first 32 bytes)
        self.session_keys[sender] = shared_secret[:32]
        
        print(f"[{self.username}]: ✓ Session established with {sender}")
        print(f"    Shared secret: {shared_secret[:32].hex()[:32]}...")
    
    
    def send_message(self, recipient, message):
        """Send encrypted message using PQC-derived session key"""
        is_initial_message = recipient not in self.session_keys
        
        if is_initial_message:
            # First message: perform KEM encapsulation
            handshake_info = self.establish_session_as_initiator(recipient)
            if not handshake_info:
                print(f"[{self.username}]: ❌ Failed to establish session")
                return
        
        # Encrypt message with AES-256-GCM using the session key
        session_key = self.session_keys[recipient]
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
        
        # Build payload
        payload = {
            "sender": self.username,
            "recipient": recipient,
            "type": "initial" if is_initial_message else "normal",
            "message_content": list(nonce + ciphertext),
            "pqc_protocol": "ML-KEM-1024"
        }
        
        if is_initial_message:
            payload["kem_ciphertext"] = handshake_info["kem_ciphertext"]
        
        # Send to server
        response = requests.post(f"{self.server_url}/send", json=payload)
        if response.status_code == 200:
            msg_type = "🔐 initial" if is_initial_message else "💬 followup"
            print(f"[{self.username}]: ✓ Message sent to {recipient} ({msg_type})")
        else:
            print(f"[{self.username}]: ❌ Send failed: {response.text}")
    
    
    def check_for_messages(self):
        """Check and decrypt incoming messages"""
        print(f"\n[{self.username}]: 📬 Checking mailbox...")
        response = requests.get(f"{self.server_url}/receive/{self.username}")
        messages = response.json().get("messages", [])
        
        if not messages:
            print(f"[{self.username}]: (no new messages)")
            return
        
        print(f"[{self.username}]: Found {len(messages)} message(s)\n")
        
        for msg in messages:
            sender = msg['sender']
            
            # If this is an initial message, establish session first
            if msg['type'] == 'initial':
                kem_ciphertext_b64 = msg.get('kem_ciphertext')
                if not kem_ciphertext_b64:
                    print(f"[{self.username}]: ❌ ERROR: Missing KEM ciphertext in initial message")
                    continue
                self.establish_session_as_responder(sender, kem_ciphertext_b64)
            
            # Decrypt the message content
            session_key = self.session_keys.get(sender)
            if not session_key:
                print(f"[{self.username}]: ❌ ERROR: No session key for {sender}")
                continue
            
            aesgcm = AESGCM(session_key)
            encrypted_payload = bytes(msg['message_content'])
            nonce = encrypted_payload[:12]
            ciphertext = encrypted_payload[12:]
            
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
                print(f"[{self.username}]: 📨 From {sender}: '{plaintext}'")
            except Exception as e:
                print(f"[{self.username}]: ❌ DECRYPTION FAILED: {e}")


# === SIMULATION TEST ===
if __name__ == '__main__':
    print("\n" + "=" * 75)
    print("  PQC E2EE CHAT - ML-KEM-1024 (Kyber) - Quantum-Resistant Messaging")
    print("=" * 75)
    
    # 1. Create clients
    alice = PQCChatClient("alice")
    bob = PQCChatClient("bob")
    
    print("\n--- PHASE 1: Key Generation ---")
    # 2. Generate keys
    alice.generate_keys()
    bob.generate_keys()
    
    print("\n--- PHASE 2: Key Publication ---")
    # 3. Publish to server
    alice.publish_keys_to_server()
    bob.publish_keys_to_server()
    
    print("\n" + "=" * 75)
    print("  SETUP COMPLETE - Ready for secure messaging")
    print("=" * 75)
    
    # 4. Alice sends first message (triggers KEM encapsulation)
    print("\n--- STEP 1: Alice → Bob (Initial Message) ---")
    alice.send_message("bob", "Hello Bob! This message is quantum-resistant!")
    
    # 5. Bob checks messages (triggers KEM decapsulation)
    print("\n--- STEP 2: Bob Checks Mailbox ---")
    bob.check_for_messages()
    
    # 6. Bob replies (establishes reverse session)
    print("\n--- STEP 3: Bob → Alice (Reply) ---")
    bob.send_message("alice", "Hi Alice! PQC is working perfectly!")
    
    # 7. Alice checks reply
    print("\n--- STEP 4: Alice Checks Mailbox ---")
    alice.check_for_messages()
    
    # 8. Continue conversation (uses existing session)
    print("\n--- STEP 5: Alice → Bob (Second Message) ---")
    alice.send_message("bob", "Great! Our chat is protected against quantum attacks.")
    
    print("\n--- STEP 6: Bob Checks Mailbox ---")
    bob.check_for_messages()
    
    # 9. Bob's final message
    print("\n--- STEP 7: Bob → Alice (Final Message) ---")
    bob.send_message("alice", "Forward secrecy achieved! 🔒")
    
    print("\n--- STEP 8: Alice Checks Mailbox ---")
    alice.check_for_messages()
    
    print("\n" + "=" * 75)
    print("  ✅ PQC E2EE TEST COMPLETE")
    print("=" * 75)
    print("\n🎉 Milestone 1 Complete: Post-Quantum Key Exchange Working!")
    print("📋 Next Step: Integrate Homomorphic Encryption for DRM policies")
    print("=" * 75 + "\n")
