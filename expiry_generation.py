from cryptography.hazmat.primitives import serialization
import hashlib

from datetime import datetime, timedelta

def generate_expiry():
    # Get the current date and time
    current_datetime = datetime.now()

    # Add one year to the current date
    expiry_datetime = current_datetime + timedelta(days=365)

    # Convert the expiry date to a timestamp (Unix timestamp)
    expiry_timestamp = expiry_datetime.timestamp()

    return int(expiry_timestamp)  # Convert to an integer
