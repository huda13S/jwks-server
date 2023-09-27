from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from kid_generation import generate_kid
from expiry_generation import generate_expiry

def generate_rsa_key_pair():
    # Generate an RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Extract the public key from the private key
    public_key = private_key.public_key()

    return private_key, public_key

def main():
    # Call the function to generate key pair
    private_key, public_key = generate_rsa_key_pair()

    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Print the private and public keys
    print("Private Key (PEM format):")
    print(private_pem.decode())

    print("\nPublic Key (PEM format):")
    print(public_pem.decode())

    # Generate Key ID (kid)
    kid = generate_kid(public_key)
    print("\nKey ID (kid):", kid)

    # Generate expiry timestamp
    expiry = generate_expiry()
    print("Expiry Timestamp:", expiry)

if __name__ == "__main__":
    main()
