from pydantic import BaseModel, Field

# Schemas for requests and responses.

class KeyGenerationRequest(BaseModel):
    key_type: str = Field(..., description="Type of the key (AES or RSA)")
    key_size: int = Field(..., description="Size of the key in bits (128, 192, 256 for AES and 1024, 2048, 3072, 4096 for RSA)")

class EncryptionRequest(BaseModel):
    key_id: str = Field(..., description="Unique identifier of a previously generated key")
    plaintext: str = Field(..., description="Text to be encrypted")
    algorithm: str = Field(..., description="Encryption algorithm to use (AES or RSA)")

class DecryptionRequest(BaseModel):
    key_id: str = Field(..., description="Unique identifier of a previously generated key")
    ciphertext: str = Field(..., description="Ciphertext to be decrypted")
    algorithm: str = Field(..., description="Decryption algorithm to use (AES or RSA)")

class HashRequest(BaseModel):
    data: str = Field(..., description="Data to be hashed")
    algorithm: str = Field(..., description="Hashing algorithm to use (SHA-224, SHA-256, SHA-384, SHA-512, MD5, BLAKE2b or BLAKE2s)")

class VerifyHashRequest(BaseModel):
    data: str = Field(..., description="Original data before hashing")
    algorithm: str = Field(..., description="Hashing algorithm used (SHA-224, SHA-256, SHA-384, SHA-512, MD5, BLAKE2b or BLAKE2s)")
    hash_value: str = Field(..., description="Hash value to verify against")

class KeyGenerationResponse(BaseModel):
    key_id: str = Field(..., description="Generated key ID")
    key_value: str = Field(..., description="Generated key value (public key for RSA)")

class EncryptionResponse(BaseModel):
    ciphertext: str = Field(..., description="Resulting ciphertext")

class DecryptionResponse(BaseModel):
    plaintext: str = Field(..., description="Decrypted plaintext")

class HashResponse(BaseModel):
    hash_value: str = Field(..., description="Generated hash value")
    algorithm: str = Field(..., description="Hashing algorithm used")

class VerifyHashResponse(BaseModel):
    is_valid: bool = Field(..., description="Indicates whether the hash matches the original data")
    message: str = Field(..., description="Additional verification message")

class ErrorResponse(BaseModel):
    error: str = Field(..., description="Error message")