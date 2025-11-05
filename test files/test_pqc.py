# test_pqc.py
import oqs

def test_kyber():
    """Test basic Kyber KEM operations"""
    print("Testing Kyber-1024 KEM...")
    
    # 1. Receiver (Bob) generates keypair
    kem_bob = oqs.KeyEncapsulation("Kyber1024")
    public_key_bob = kem_bob.generate_keypair()
    print(f"✓ Bob's public key generated ({len(public_key_bob)} bytes)")
    
    # 2. Sender (Alice) encapsulates a shared secret using Bob's public key
    kem_alice = oqs.KeyEncapsulation("Kyber1024")
    ciphertext, shared_secret_alice = kem_alice.encap_secret(public_key_bob)
    print(f"✓ Alice encapsulated secret ({len(ciphertext)} bytes ciphertext)")
    print(f"  Shared secret (Alice): {shared_secret_alice.hex()[:32]}...")
    
    # 3. Receiver (Bob) decapsulates to get the same shared secret
    shared_secret_bob = kem_bob.decap_secret(ciphertext)
    print(f"  Shared secret (Bob):   {shared_secret_bob.hex()[:32]}...")
    
    # 4. Verify both secrets match
    assert shared_secret_alice == shared_secret_bob, "Secrets don't match!"
    print("✓ SUCCESS: Both parties derived the same shared secret!\n")
    
    return True

if __name__ == '__main__':
    test_kyber()
    print("liboqs is working correctly! Ready to integrate into client.py")
