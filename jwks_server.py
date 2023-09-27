import datetime
import jwt
import base64
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate

# Initialize your Flask app
app = Flask(__name__)

# Load the private key from your private_key.pem file
with open("private_keys/private_key.pem", "rb") as private_key_file:
    private_key_str = private_key_file.read()

private_key = serialization.load_pem_private_key(
    private_key_str,
    password=None,
    backend=default_backend()
)

# Load the public key from your public_key.pem file
with open("python code/public_key.pem", "rb") as public_key_file:
    public_key_str = public_key_file.read()

public_key = load_pem_x509_certificate(public_key_str, default_backend()).public_key()

# Implement your RESTful JWKS endpoint
@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    # Generate a JWKS response containing your public key
    jwks_response = {
        "keys": [
            {
                "kid": "kid1",  # Updated with the actual key ID (kid)
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, "big")).rstrip(b"="),
                "e": base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes(3, "big")).rstrip(b"=")
            }
        ]
    }

    return jsonify(jwks_response)

# Implement your /auth endpoint
@app.route("/auth", methods=["POST"])
def authenticate():
    # Get the "expired" query parameter
    expired = request.args.get("expired")

    if expired:
        # Sign a JWT with the expired private key and expiry
        expiration = datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
        expiration_timestamp = int(expiration.timestamp())
        payload = {
            "sub": "user123",  # Replace with the actual user identifier
            "exp": expiration_timestamp
        }
        token = jwt.encode(payload, private_key_str, algorithm="RS256")
    else:
        # Sign a JWT with the current private key
        payload = {
            "sub": "user123",  # Replace with the actual user identifier
            "exp": int((datetime.datetime.utcnow() + datetime.timedelta(minutes=30)).timestamp())
        }
        token = jwt.encode(payload, private_key_str, algorithm="RS256")

    return jsonify({"token": token.decode("utf-8")})

# Run the Flask app on port 8080
if __name__ == "__main__":
    app.run(port=8080)
