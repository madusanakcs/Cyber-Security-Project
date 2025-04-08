
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

def generate_key(key_size):

    if key_size not in [128, 192, 256]:
        return {"error": "Invalid key size. Supported sizes are 128, 192, 256"}

    # Generate a random key
    key = os.urandom(key_size // 8)

    # Return key
    return base64.b64encode(key).decode('utf-8')

    
def encrypt(key, plaintext):
    # Decode the base64 key
    key = base64.b64decode(key.encode('utf-8'))

    # Pad the plaintext to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Encrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {"ciphertext": base64.b64encode(iv + ciphertext).decode('utf-8')}


def decrypt(key, ciphertext):
    # Decode the base64 key
    key = base64.b64decode(key.encode('utf-8'))

    # Decode the Base64-encoded ciphertext
    decoded_ciphertext = base64.b64decode(ciphertext.encode('utf-8'))

    # Extract the IV and the actual ciphertext
    iv = decoded_ciphertext[:16]
    actual_ciphertext = decoded_ciphertext[16:]

    # Decrypt the data
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Unpad the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return {"plaintext": plaintext.decode('utf-8')}



