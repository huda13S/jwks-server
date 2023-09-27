from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Generate a sample RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Serialize the public key to PEM format
public_key_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Create a JWKS dictionary
jwks = {
    "keys": [
        {
            "kid": "sample-key-1",  # Unique key ID
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",  # Use for signing
            "n": public_key_pem.decode('utf-8')
        }
    ]
}

# Hello, World! route
@app.route('/')
def hello_world():
    return 'Hello, World!'

# JWKS endpoint
@app.route('/jwks', methods=['GET'])
def get_jwks():
    return jsonify(jwks)

# Authentication endpoint
@app.route('/auth', methods=['POST'])
def authenticate():
    # Replace this with your authentication logic
    username = request.json.get('username')
    password = request.json.get('password')

    # Perform authentication here (e.g., check credentials)
    if username == 'userABC' and password == 'password123':
        # If authenticated, create a JWT token (replace with your JWT logic)
        # For demonstration, we're using a simple string as a token
        token = 'your_jwt_token_here'
        return jsonify({"token": token})
    else:
        return jsonify({"error": "Authentication failed"}), 401

if __name__ == '__main__':
    app.run(debug=True, port=8080)
