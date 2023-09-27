from cryptography.hazmat.primitives import serialization
import hashlib

def generate_kid(public_key):
    # Serialize the public key to bytes
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Calculate the SHA-256 hash of the serialized public key
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    
    # Convert the hash to a hex string to create the kid
    kid = sha256_hash.hex()
    
    return kid

