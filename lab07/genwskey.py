import base64
import os

def generate_websocket_key():
    # Generate 16 random bytes
    key = os.urandom(16)
    # Encode these bytes in base64
    return base64.b64encode(key).decode('utf-8')

# Generate the SEC_WEBSOCKET_KEY
websocket_key = generate_websocket_key()
print(websocket_key)