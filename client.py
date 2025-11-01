# --- FINAL client.py for X3DH ---

import os
import requests
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Helper Functions ---
def public_key_to_base64(key):
    return base64.b64encode(key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )).decode('utf-8')

def base64_to_public_key(b64_key):
    key_bytes = base64.b64decode(b64_key)
    return x25519.X25519PublicKey.from_public_bytes(key_bytes)


class ChatClient:
    def __init__(self, username, server_url="http://127.0.0.1:5000"):
        self.username = username
        self.server_url = server_url
        print(f"Client for '{self.username}' initialized.")
        self.identity_key = None
        self.signed_pre_key = None
        self.one_time_pre_keys = {} # Store as dict for easy lookup
        self.session_keys = {}

    def generate_keys(self, num_ot_keys=10):
        print(f"[{self.username}]: Generating keys...")
        self.identity_key = x25519.X25519PrivateKey.generate()
        self.signed_pre_key = x25519.X25519PrivateKey.generate()
        for i in range(num_ot_keys):
            key = x25519.X25519PrivateKey.generate()
            # Store the private key, using its public part as a key for lookup
            self.one_time_pre_keys[public_key_to_base64(key.public_key())] = key
        print(f"[{self.username}]: Key generation complete.")
        
    def publish_keys_to_server(self):
        print(f"[{self.username}]: Publishing keys to server...")
        bundle = {
            'username': self.username,
            'identity_key': public_key_to_base64(self.identity_key.public_key()),
            'signed_pre_key': public_key_to_base64(self.signed_pre_key.public_key()),
            'one_time_pre_keys': list(self.one_time_pre_keys.keys()),
        }
        requests.post(f"{self.server_url}/publish_keys", json=bundle)
        print(f"[{self.username}]: Successfully published keys.")

    def _derive_key(self, dh_results):
        """Helper to run the concatenated DH results through our KDF."""
        hkdf_input = b"".join(dh_results)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake_data')
        return hkdf.derive(hkdf_input)

    def establish_session_as_initiator(self, recipient):
        """Alice's side of the handshake."""
        print(f"[{self.username}]: Initiating session with {recipient}...")
        response = requests.get(f"{self.server_url}/get_keys/{recipient}")
        key_bundle = response.json()
        
        IKb = base64_to_public_key(key_bundle['identity_key'])
        SPKb = base64_to_public_key(key_bundle['signed_pre_key'])
        OPKb_b64 = key_bundle['one_time_pre_key']
        OPKb = base64_to_public_key(OPKb_b64)
        
        EKa = x25519.X25519PrivateKey.generate()
        
        dh1 = self.identity_key.exchange(SPKb)
        dh2 = EKa.exchange(IKb)
        dh3 = EKa.exchange(SPKb)
        dh4 = EKa.exchange(OPKb)
        
        derived_key = self._derive_key([dh1, dh2, dh3, dh4])
        self.session_keys[recipient] = derived_key
        
        print(f"[{self.username}]: Derived secret for {recipient}: {derived_key.hex()}")
        # Return public info Bob will need
        return {
            "IKa": public_key_to_base64(self.identity_key.public_key()),
            "EKa": public_key_to_base64(EKa.public_key()),
            "OPKb_used": OPKb_b64
        }

    def establish_session_as_responder(self, sender, initial_message):
        """Bob's side of the handshake."""
        print(f"[{self.username}]: Establishing session from {sender}'s first message...")
        
        IKa = base64_to_public_key(initial_message['IKa'])
        EKa = base64_to_public_key(initial_message['EKa'])
        OPKb_used_b64 = initial_message['OPKb_used']

        # Find the private one-time key that Alice used
        OPKb_private = self.one_time_pre_keys[OPKb_used_b64]

        dh1 = self.signed_pre_key.exchange(IKa)
        dh2 = self.identity_key.exchange(EKa)
        dh3 = self.signed_pre_key.exchange(EKa)
        dh4 = OPKb_private.exchange(EKa)
        
        derived_key = self._derive_key([dh1, dh2, dh3, dh4])
        self.session_keys[sender] = derived_key
        
        print(f"[{self.username}]: Derived secret for {sender}: {derived_key.hex()}")

    def send_message(self, recipient, message):
        is_initial_message = recipient not in self.session_keys
        
        if is_initial_message:
            # This is the first message, so we must perform the X3DH handshake.
            handshake_info = self.establish_session_as_initiator(recipient)
        
        # Encrypt the message with the newly established session key
        session_key = self.session_keys[recipient]
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
        
        # Package the final payload
        payload = {
            "sender": self.username,
            "recipient": recipient,
            "type": "initial" if is_initial_message else "normal",
            "message_content": list(nonce + ciphertext)
        }
        if is_initial_message:
            payload.update(handshake_info)
            
        requests.post(f"{self.server_url}/send", json=payload)
        print(f"[{self.username}]: Message sent to {recipient}.")

    def check_for_messages(self):
        print(f"\n[{self.username}]: Checking for messages...")
        response = requests.get(f"{self.server_url}/receive/{self.username}")
        messages = response.json().get("messages", [])
        
        if not messages:
            print(f"[{self.username}]: No new messages.")
            return

        for msg in messages:
            sender = msg['sender']
            
            if msg['type'] == 'initial':
                # This is the first message from this user, we must establish the session.
                self.establish_session_as_responder(sender, msg)
            
            # Decrypt the message
            session_key = self.session_keys.get(sender)
            if not session_key:
                print(f"[{self.username}]: Error - No session key for {sender}. Cannot decrypt.")
                continue
            
            aesgcm = AESGCM(session_key)
            encrypted_payload = bytes(msg['message_content'])
            nonce = encrypted_payload[:12]
            ciphertext = encrypted_payload[12:]
            
            try:
                decrypted_message = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
                print(f"  >> New message from {sender}: '{decrypted_message}'")
            except Exception as e:
                print(f"DECRYPTION FAILED: {e}")

# --- The Final Simulation ---
if __name__ == '__main__':
    # 1. Setup: Create clients and publish their keys
    alice = ChatClient("alice")
    bob = ChatClient("bob")
    alice.generate_keys()
    bob.generate_keys()
    alice.publish_keys_to_server()
    bob.publish_keys_to_server()
    print("\n--- SETUP COMPLETE ---")

    # 2. Alice sends the first message. This triggers the full X3DH handshake.
    alice.send_message("bob", "Hello Bob, this should be secure!")

    # 3. Bob checks his messages. This triggers his side of the calculation and decryption.
    bob.check_for_messages()
    
    # 4. Bob replies to show the session is established and works both ways.
    bob.send_message("alice", "Hi Alice, I got it! The channel is secure.")
    
    # 5. Alice checks for Bob's reply.
    alice.check_for_messages()