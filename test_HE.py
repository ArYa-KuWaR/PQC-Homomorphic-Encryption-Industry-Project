# test_he.py - Test Homomorphic Encryption with TenSEAL
import tenseal as ts

print("=" * 60)
print("Testing TenSEAL - Homomorphic Encryption")
print("=" * 60)

# 1. Setup context (encryption parameters)
context = ts.context(
    ts.SCHEME_TYPE.BFV,  # Integer arithmetic scheme
    poly_modulus_degree=4096,
    plain_modulus=1032193
)
context.generate_galois_keys()
context.generate_relin_keys()

print("✓ HE Context created")

# 2. Encrypt a play count (starting at 0)
play_count = 0
encrypted_count = ts.bfv_vector(context, [play_count])
print(f"✓ Encrypted play count: {play_count}")

# 3. Homomorphically increment (server-side, without decryption)
print("\n--- Simulating Server-Side Operations ---")
for i in range(1, 4):
    encrypted_count = encrypted_count + [1]  # Add 1 homomorphically
    print(f"  Increment {i}: Count updated (still encrypted)")

# 4. Decrypt to verify (client-side only)
final_count = encrypted_count.decrypt()[0]
print(f"\n✓ Decrypted final count: {final_count}")
print(f"✓ Expected: 3, Got: {final_count}")

assert final_count == 3, "Homomorphic addition failed!"

print("\n" + "=" * 60)
print("✅ SUCCESS: Homomorphic Encryption Working!")
print("=" * 60)
