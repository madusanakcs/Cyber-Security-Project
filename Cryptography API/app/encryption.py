from app import AES, RSA
from app import database
import uuid

# These functions are a common interface for AES and RSA encryption.

def generate_key(key_type, key_size):

    if key_type == "AES":
        key = AES.generate_key(key_size)
    elif key_type == "RSA":
        key = RSA.generate_key(key_size)
    else: 
        return {"error": "Invalid key type. AES and RSA are supported."}
    
    if type(key) == dict and "error" in key:   # Error message
        return key
    
    # Generate key ID and store in database
    key_id = uuid.uuid4().hex[:8]
    key_response = database.store_key(key_type, key_id, key)

    return key_response

    
def encrypt(key_id, plaintext, algorithm):
    # Check whether algorithm is supported
    if algorithm not in ["AES", "RSA"]: 
        return {"error": "Invalid algorithm. AES and RSA are supported."}

    # Look up key from the database
    key = database.get_key(algorithm, key_id)
    if not key:
        return {"error": "Key not found"}

    if algorithm == "AES":
        return AES.encrypt(key, plaintext)
    elif algorithm == "RSA":
        return RSA.encrypt(key, plaintext)
    
    
def decrypt(key_id, ciphertext, algorithm):
    # Check whether algorithm is supported
    if algorithm not in ["AES", "RSA"]: 
        return {"error": "Invalid algorithm. AES and RSA are supported."}
    
    # Look up key from the database
    key = database.get_key(algorithm, key_id)
    if not key:
        return {"error": "Key not found"}

    if algorithm == "AES":
        return AES.decrypt(key, ciphertext)
    elif algorithm == "RSA":
        return RSA.decrypt(key, ciphertext)