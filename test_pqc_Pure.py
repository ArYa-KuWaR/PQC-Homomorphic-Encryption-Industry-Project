# test_pqc_pure.py (fixed for pqcrypto 0.3.4)
from secrets import compare_digest
from pqcrypto.kem.ml_kem_1024 import generate_keypair, encrypt, decrypt

print("=" * 60)
print("Testing ML-KEM-1024 (Kyber) via pqcrypto 0.3.4")
print("=" * 60)

# Bob generates keypair
public_key_bob, secret_key_bob = generate_keypair()
print(f"PK bytes: {len(public_key_bob)}, SK bytes: {len(secret_key_bob)}")

# Alice encapsulates
ciphertext, shared_secret_alice = encrypt(public_key_bob)
print(f"CT bytes: {len(ciphertext)}, SS(A) prefix: {shared_secret_alice.hex()[:32]}...")

# Bob decapsulates
shared_secret_bob = decrypt(secret_key_bob, ciphertext)
print(f"SS(B) prefix: {shared_secret_bob.hex()[:32]}...")

# Verify
assert compare_digest(shared_secret_alice, shared_secret_bob)
print("SUCCESS: Shared secrets match.")
