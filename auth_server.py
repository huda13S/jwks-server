from cryptography.hazmat.primitives import serialization
import datetime
import jwt
import base64
from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Load the private key from your private_key.pem file
with open("private_key.pem", "rb") as private_key_file:
    private_key_str = private_key_file.read()

# Use the private key as bytes directly
private_key = private_key_str

# Load the public key from your public_key.pem file
with open("public_key.pem", "rb") as public_key_file:
    public_key_str = public_key_file.read()

public_key = serialization.load_pem_public_key(public_key_str, backend=default_backend())

def generate_jwks():
    try:
        # Generate a JWKS response containing your public key
        jwks_response = {
            "keys": [
                {
                    "kid": "09po90op",  # Updated with the actual key ID (kid)
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "n": base64.urlsafe_b64encode(public_key.public_numbers().n.to_bytes(256, "big")).decode("utf-8"),
                    "e": base64.urlsafe_b64encode(public_key.public_numbers().e.to_bytes(3, "big")).decode("utf-8"),
                }
            ]
        }

        return jwks_response

    except Exception as e:
        return None

# Implement your RESTful JWKS endpoint
@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    try:
        jwks_response = generate_jwks()

        if jwks_response:
            return jsonify(jwks_response)
        else:
            return jsonify({"error": "Failed to generate valid JWK"}), 500

    except Exception as e:
        return jsonify({"error": f"Unexpected error during JWKS generation: {str(e)}"}), 500

# Implement your /auth endpoint
@app.route("/auth", methods=["POST"])
def authenticate():
    try:
        # Get the "expired" query parameter
        expired = request.args.get("expired")

        if expired:
            # Sign a JWT with the expired private key and expiry
            expiration = datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
            expiration_timestamp = int(expiration.timestamp())
        else:
            # Sign a JWT with the current private key
            expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            expiration_timestamp = int(expiration.timestamp())

        # Specify the "kid" in the JWT header
        kid = "09po90op"

        payload = {"sub": "hayalsuleman@gmail.com", "exp": expiration_timestamp}
        
        # Include the "kid" in the JWT header
        headers = {"kid": kid}
        
        # Sign the JWT with the specified key and header
        token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)

        return jsonify({"token": token}), 200

    except jwt.PyJWTError as e:
        return jsonify({"error": f"JWT generation error: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": f"Unexpected error during authentication: {str(e)}"}), 500

# Run the Flask app on port 8080
if __name__ == "__main__":
    app.run(port=8080)

