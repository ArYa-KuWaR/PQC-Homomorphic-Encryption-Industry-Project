# drm_policy.py - DRM with Homomorphic Encryption
import tenseal as ts
import base64
import pickle

class DRMPolicy:
    """DRM policy manager using homomorphic encryption"""
    
    def __init__(self):
        """Initialize HE context"""
        # Setup encryption context for integer operations
        self.context = ts.context(
            ts.SCHEME_TYPE.BFV,
            poly_modulus_degree=4096,
            plain_modulus=1032193
        )
        self.context.generate_galois_keys()
        self.context.generate_relin_keys()
        
        print("[DRM] Homomorphic encryption context initialized")
    
    def get_public_context(self):
        """Get serialized public context (for server)"""
        # Serialize context without secret key
        ctx_copy = self.context.copy()
        ctx_copy.make_context_public()
        return ctx_copy.serialize()
    
    def create_license(self, max_plays=10):
        """
        Create a DRM license with encrypted play counter
        Returns: Serialized encrypted counter + max plays limit
        """
        # Encrypt initial play count (0)
        encrypted_counter = ts.bfv_vector(self.context, [0])
        
        license_data = {
            'encrypted_counter': encrypted_counter.serialize(),
            'max_plays': max_plays,
            'public_context': self.get_public_context()
        }
        
        print(f"[DRM] License created: Max {max_plays} plays")
        return license_data
    
    def increment_counter(self, encrypted_counter_bytes, public_context_bytes):
        """
        Server-side: Increment play counter homomorphically
        This happens WITHOUT decrypting the counter
        """
        # Deserialize public context
        pub_ctx = ts.context_from(public_context_bytes)
        
        # Deserialize encrypted counter
        enc_counter = ts.bfv_vector_from(pub_ctx, encrypted_counter_bytes)
        
        # Homomorphically add 1
        enc_counter = enc_counter + [1]
        
        print("[DRM] Play counter incremented (homomorphically)")
        return enc_counter.serialize()
    
    def verify_limit(self, encrypted_counter_bytes, max_plays):
        """
        Client-side: Decrypt and check if limit exceeded
        Only the client with secret key can do this
        """
        # Deserialize and decrypt
        enc_counter = ts.bfv_vector_from(self.context, encrypted_counter_bytes)
        current_count = enc_counter.decrypt()[0]
        
        allowed = current_count < max_plays
        
        status = "ALLOWED" if allowed else "DENIED"
        print(f"[DRM] Playback {status}: {current_count}/{max_plays} plays used")
        
        return {
            'allowed': allowed,
            'current_count': current_count,
            'max_plays': max_plays
        }


# === TEST ===
if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("  DRM POLICY TEST - Homomorphic Play Counter")
    print("=" * 70)
    
    # 1. Client creates DRM policy
    drm = DRMPolicy()
    
    # 2. Create license (max 3 plays for testing)
    license_data = drm.create_license(max_plays=3)
    
    print("\n--- Simulating Server Operations (No Decryption) ---")
    
    # 3. Simulate 3 plays (server increments without knowing count)
    encrypted_counter = license_data['encrypted_counter']
    public_ctx = license_data['public_context']
    
    for play_num in range(1, 4):
        print(f"\nPlay {play_num}:")
        encrypted_counter = drm.increment_counter(encrypted_counter, public_ctx)
    
    print("\n--- Client Verifies Limit ---")
    
    # 4. Client checks if more plays allowed
    result = drm.verify_limit(encrypted_counter, license_data['max_plays'])
    
    # 5. Try one more play (should be denied)
    print("\nAttempting play 4:")
    encrypted_counter = drm.increment_counter(encrypted_counter, public_ctx)
    result = drm.verify_limit(encrypted_counter, license_data['max_plays'])
    
    print("\n" + "=" * 70)
    print("✅ DRM POLICY TEST COMPLETE")
    print("=" * 70)
