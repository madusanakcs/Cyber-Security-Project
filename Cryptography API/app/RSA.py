from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

def generate_key(key_size):
    if key_size not in [1024, 2048, 3072, 4096]:
        return {"error": "Invalid key size. Supported sizes are 1024, 2048, 3072, 4096"}

    # Generate private and public key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()

    # Serialize public key to PEM and encode to Base64
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_base64 = base64.b64encode(public_pem).decode('utf-8')

    # Serialize private key to PEM and encode to Base64
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    private_key_base64 = base64.b64encode(private_pem).decode('utf-8')

    return {
        "public_key": public_key_base64,
        "private_key": private_key_base64
    }

def encrypt(keys, plaintext):

    try:
        # Decode and deserialize public key
        public_key_base64 = keys["public_key"]
        public_key_pem = base64.b64decode(public_key_base64)

        public_key = serialization.load_pem_public_key(public_key_pem)

        # Encrypt using public key and OAEP padding
        encrypted = public_key.encrypt(
            plaintext.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Encode ciphertext as base64
        return {"ciphertext": base64.b64encode(encrypted).decode('utf-8')}
    except Exception as e:
        return {"error": str(e)}

def decrypt(keys, ciphertext):

    try:
        # Decode and deserialize private key
        private_key_base64 = keys["private_key"]
        private_key_pem = base64.b64decode(private_key_base64)

        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None
        )

        # Decrypt using public key and OAEP padding
        decrypted = private_key.decrypt(
            base64.b64decode(ciphertext),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {"plaintext": decrypted.decode('utf-8')}
    except Exception as e:
        return {"error": str(e)}
