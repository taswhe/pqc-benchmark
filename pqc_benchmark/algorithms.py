from dataclasses import dataclass
from time import time
import oqs
import sys
from Cryptodome.Signature import eddsa, pkcs1_15, DSS
from Cryptodome.PublicKey import ECC, RSA
from Cryptodome.Hash import SHA256

# Add path to botan3 module
sys.path.append('/usr/local/lib/python3/site-packages')
import botan3

@dataclass
class Algorithm:
    name: str
    pub_key_size_bytes: int  # Public key size in bytes
    priv_key_size_bytes: int  # Private key size in bytes
    signature_size_min_bytes: int  # Minimum signature size in bytes
    signature_size_max_bytes: int  # Maximum signature size in bytes
    type: str
    oqs_alg: str = None  # OQS algorithm name
    botan_alg: str = None  # Botan algorithm name
    botan_params: str = None  # Botan algorithm parameters

def get_supported_algorithms():
    """Get list of supported algorithms from OQS library"""
    # Use the get_enabled_sig_mechanisms function
    supported = oqs.get_enabled_sig_mechanisms()
    print("Supported OQS algorithms:", supported)
    return supported

def get_all_algorithms():
    """Return all algorithms combined"""
    supported_algs = get_supported_algorithms()
    
    # Post-Quantum Cryptography Algorithms
    pqc_algs = []
    potential_algs = [
        # SPHINCS+ variants
        # f variant
        ("SLH-DSA-128f (SPHINCS+)", 32, 64, 17088, 17088, "PQC", "SPHINCS+-SHA2-128f-simple"),
        ("SLH-DSA-192f (SPHINCS+)", 48, 96, 35664, 35664, "PQC", "SPHINCS+-SHA2-192f-simple"),
        ("SLH-DSA-256f (SPHINCS+)", 64, 128, 49856, 49856, "PQC", "SPHINCS+-SHA2-256f-simple"),
        # s variant
        ("SLH-DSA-128s (SPHINCS+)", 32, 64, 7856, 7856, "PQC", "SPHINCS+-SHA2-128s-simple"),
        ("SLH-DSA-192s (SPHINCS+)", 48, 96, 16224, 16224, "PQC", "SPHINCS+-SHA2-192s-simple"),
        ("SLH-DSA-256s (SPHINCS+)", 64, 128, 29792, 29792, "PQC", "SPHINCS+-SHA2-256s-simple"),
        
        # Falcon variants (signature sizes are variable)
        ("FN-DSA-512 (Falcon)", 897, 1281, 649, 666, "PQC", "Falcon-512"),
        ("FN-DSA-1024 (Falcon)", 1793, 2305, 1261, 1280, "PQC", "Falcon-1024"),
        
        # Dilithium variants
        ("ML-DSA-44 (Dilithium)", 1312, 2560, 2420, 2420, "PQC", "ML-DSA-44"),
        ("ML-DSA-65 (Dilithium)", 1952, 4032, 3309, 3309, "PQC", "ML-DSA-65"),
        ("ML-DSA-87 (Dilithium)", 2592, 4896, 4627, 4627, "PQC", "ML-DSA-87"),
    ]
    
    for name, pub_size, priv_size, sig_min_size, sig_max_size, alg_type, oqs_name in potential_algs:
        if oqs_name in supported_algs:
            pqc_algs.append(Algorithm(name, pub_size, priv_size, sig_min_size, sig_max_size, alg_type, oqs_name))

    # XMSS variants from Botan
    try:
        # Check if Botan with XMSS is available by attempting to create a test key
        rng = botan3.RandomNumberGenerator()
        try:
            # Try to create a small test key to verify XMSS support
            test_key = botan3.PrivateKey.create("XMSS", "XMSS-SHA2_10_256", rng)
            xmss_supported = True
            print("Botan XMSS support detected")
        except Exception:
            xmss_supported = False
            print("Botan XMSS support not available")
            
        if xmss_supported:
            # Add XMSS variants
            xmss_variants = [
                # Name, pub_size, priv_size, sig_min, sig_max, type, oqs_name, botan_alg, botan_params
                ("XMSS-SHA2_10_256", 64, 132, 2500, 2500, "PQC", None, "XMSS", "XMSS-SHA2_10_256"),
                #("XMSS-SHA2_16_256", 64, 132, 2500, 2500, "PQC", None, "XMSS", "XMSS-SHA2_16_256"),
                # ("XMSS-SHA2_20_256", 64, 132, 2500, 2500, "PQC", None, "XMSS", "XMSS-SHA2_20_256"),
            ]
            
            for name, pub_size, priv_size, sig_min_size, sig_max_size, alg_type, _, botan_alg, botan_params in xmss_variants:
                pqc_algs.append(Algorithm(
                    name, pub_size, priv_size, sig_min_size, sig_max_size, 
                    alg_type, None, botan_alg, botan_params
                ))
                print(f"Added XMSS variant: {name}")
    except ImportError as e:
        print(f"Botan import failed: {e}")

    # Classical Digital Signature Algorithms
    classical_algs = [
        Algorithm("RSA-2048", 256, 256, 256, 256, "Classical"),
        Algorithm("RSA-4096", 512, 512, 512, 512, "Classical"),
        Algorithm("ECDSA-secp256r1", 32, 32, 64, 64, "Classical"),
        Algorithm("Ed25519", 32, 32, 64, 64, "Classical"),
    ]

    return pqc_algs + classical_algs

def generate_keys(algo: Algorithm):
    """Generate and time key generation"""
    if algo.type == "PQC":
        if algo.oqs_alg:  # OQS-based algorithm
            signer = oqs.Signature(algo.oqs_alg)
            start = time()
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
            
            # Validate key sizes
            if len(public_key) != algo.pub_key_size_bytes:
                raise ValueError(f"Public key size {len(public_key)} bytes doesn't match expected {algo.pub_key_size_bytes} bytes")
            if len(secret_key) != algo.priv_key_size_bytes:
                raise ValueError(f"Private key size {len(secret_key)} bytes doesn't match expected {algo.priv_key_size_bytes} bytes")
                
            end = time()
            return {
                'signer': signer,
                'public_key': public_key,
                'keygen_time': end - start
            }
        elif algo.botan_alg:  # Botan-based algorithm (XMSS)
            rng = botan3.RandomNumberGenerator()
            start = time()
            private_key = botan3.PrivateKey.create(
                algo.botan_alg,  # Algorithm name (XMSS)
                algo.botan_params,  # Parameter set
                rng
            )
            public_key = private_key.get_public_key()
            end = time()
            
            return {
                'private_key': private_key,
                'public_key': public_key,
                'rng': rng,
                'keygen_time': end - start
            }
    else:
        if algo.name.startswith("RSA"):
            start = time()
            key = RSA.generate(algo.pub_key_size_bytes * 8)
            end = time()
            return {
                'key': key,
                'keygen_time': end - start
            }
        elif algo.name.startswith("Ed"):
            start = time()
            key = ECC.generate(curve='ed25519')
            end = time()
            return {
                'key': key,
                'keygen_time': end - start
            }
        else:
            start = time()
            key = ECC.generate(curve='P-256')
            end = time()
            return {
                'key': key,
                'keygen_time': end - start
            }

def benchmark_signature(algo: Algorithm, keys, message: bytes, iterations=100):
    """Benchmark signing performance using pre-generated keys"""
    if algo.type == "PQC":
        if algo.oqs_alg:  # OQS-based algorithm
            signer = keys['signer']
            public_key = keys['public_key']
            
            # Time signing
            start = time()
            for _ in range(iterations):
                signature = signer.sign(message)
            end = time()

            # Verify signature size is within allowed range
            signature_bytes = len(signature)
            if not (algo.signature_size_min_bytes <= signature_bytes <= algo.signature_size_max_bytes):
                raise ValueError(f"Signature size {signature_bytes} bytes is not within expected range of {algo.signature_size_min_bytes}-{algo.signature_size_max_bytes} bytes")
            
            # Time verification
            verify_start = time()
            for _ in range(iterations):
                if not signer.verify(message, signature, public_key):
                    raise ValueError("Signature verification failed")
            verify_end = time()
            
            return {
                'sign_time': (end - start) / iterations,
                'verify_time': (verify_end - verify_start) / iterations
            }
        elif algo.botan_alg:  # Botan-based algorithm (XMSS)
            private_key = keys['private_key']
            public_key = keys['public_key']
            rng = keys['rng']
            
            # Create signer/verifier objects
            signer = botan3.PKSign(private_key, "EMSA1(SHA-256)")
            verifier = botan3.PKVerify(public_key, "EMSA1(SHA-256)")
            
            # Time signing
            start = time()
            for _ in range(iterations):
                signer.update(message)
                signature = signer.finish(rng)
                signer = botan3.PKSign(private_key, "EMSA1(SHA-256)")  # Reset signer
            end = time()
            
            # Time verification
            verify_start = time()
            for _ in range(iterations):
                verifier.update(message)
                is_valid = verifier.check_signature(signature)
                if not is_valid:
                    raise ValueError("Signature verification failed")
                verifier = botan3.PKVerify(public_key, "EMSA1(SHA-256)")  # Reset verifier
            verify_end = time()
            
            return {
                'sign_time': (end - start) / iterations,
                'verify_time': (verify_end - verify_start) / iterations
            }
    else:
        if algo.name.startswith("RSA"):
            key = keys['key']
            hash_obj = SHA256.new(message)
            signer = pkcs1_15.new(key)
            
            # Time signing
            start = time()
            for _ in range(iterations):
                signature = signer.sign(hash_obj)
            end = time()
            
            # Time verification
            verifier = pkcs1_15.new(key)
            verify_start = time()
            for _ in range(iterations):
                try:
                    verifier.verify(hash_obj, signature)
                except ValueError:
                    pass
            verify_end = time()
            
        elif algo.name.startswith("Ed"):
            key = keys['key']
            signer = eddsa.new(key, 'rfc8032')
            
            # Time signing
            start = time()
            for _ in range(iterations):
                signature = signer.sign(message)
            end = time()
            
            # Time verification
            verifier = eddsa.new(key, 'rfc8032')
            verify_start = time()
            for _ in range(iterations):
                verifier.verify(message, signature)
            verify_end = time()
            
        else:
            key = keys['key']
            hash_obj = SHA256.new(message)
            signer = DSS.new(key, 'fips-186-3')
            
            # Time signing
            start = time()
            for _ in range(iterations):
                signature = signer.sign(hash_obj)
            end = time()
            
            # Time verification
            verifier = DSS.new(key, 'fips-186-3')
            verify_start = time()
            for _ in range(iterations):
                try:
                    verifier.verify(hash_obj, signature)
                except ValueError:
                    pass
            verify_end = time()
        
        return {
            'sign_time': (end - start) / iterations,
            'verify_time': (verify_end - verify_start) / iterations
        }
