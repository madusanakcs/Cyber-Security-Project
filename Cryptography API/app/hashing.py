
import hashlib
import base64

hash_functions = {
    "SHA-1"  : hashlib.sha1,
    "SHA-224": hashlib.sha224,
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
    "SHA-512": hashlib.sha512,
    "MD5"    : hashlib.md5,
    "BLAKE2B": hashlib.blake2b,
    "BLAKE2S": hashlib.blake2s
}

# Function to get hash
def get_hash(data: str, algorithm: str):
    return hash_functions[algorithm](data.encode()).digest()

### ====== Hashing ====== ###
def generate_hash(data, algorithm):
    algorithm = algorithm.upper()
    
    if algorithm not in hash_functions:
        return {"error": "Invalid hashing algorithm. Use 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', 'MD5' , 'BLAKE2b' or 'BLAKE2s'. "}

    hash_value = get_hash(data, algorithm)

    return {
        "hash_value": base64.b64encode(hash_value).decode(),  # Convert computed hash to base64
        "algorithm": algorithm
    }


### ====== Verifying Hashing ====== ###
def verify_hash(data, algorithm, hash_value):
    algorithm = algorithm.upper()

    if algorithm not in hash_functions:
        return {"error": "Invalid hashing algorithm. Use 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', 'MD5' , 'BLAKE2b' or 'BLAKE2s'. "}

    computed_hash = get_hash(data, algorithm)
    computed_hash_b64 = base64.b64encode(computed_hash).decode()  # Convert computed hash to base64

    is_valid = computed_hash_b64 == hash_value  # Compare with given hash

    return {
        "is_valid": is_valid,
        "message": "Hash matches the data." if is_valid else "Hash does not match."
    }
