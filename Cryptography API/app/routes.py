from app import app
from flask import request, jsonify
from app.dto import *
from pydantic import ValidationError
from app import encryption, hashing
from flasgger import swag_from

def handle_request(request_model, handler):
    # Generic function to validate request and call the handler. 
    try:
        req_data = request.get_json()
        req = request_model(**req_data)  # Validate input
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400  # Return a 400 Bad Request
    
    try:
        response = handler(req)  # Call the function that does the actual work
    except Exception as e:
        return jsonify({"error": str(e)}), 400  # Return a 400 Bad Request
    
    if "error" in response:
        return jsonify(response), 400  # Return error response
    
    return jsonify(response), 200  # Return success response


@app.post("/generate-key")
@swag_from({
    "tags": ["Encryption"],
    "summary": "Generate a new encryption key",
    "parameters": [
        {
            "name": "body",
            "in": "body",
            "schema": KeyGenerationRequest.model_json_schema(),
            "required": True
        }
    ],
    "responses": {
        "200": {
            "description": "Successfully generated key ID and (public) key",
            "schema": KeyGenerationResponse.model_json_schema()
        },
        "400": {
            "description": "Invalid request",
            "schema": ErrorResponse.model_json_schema()
        }
    }
})
def generate_key():
    return handle_request(KeyGenerationRequest, lambda req: encryption.generate_key(req.key_type, req.key_size))


@app.post("/encrypt")
@swag_from({
    "tags": ["Encryption"],
    "summary": "Encrypt a plaintext message with the key corresponding to given key ID",
    "parameters": [
        {
            "name": "body",
            "in": "body",
            "schema": EncryptionRequest.model_json_schema(),
            "required": True
        }
    ],
    "responses": {
        "200": {
            "description": "Successfully encrypted ciphertext",
            "schema": EncryptionResponse.model_json_schema()
        },
        "400": {
            "description": "Invalid request",
            "schema": ErrorResponse.model_json_schema()
        }
    }
})
def encrypt():
    return handle_request(EncryptionRequest, lambda req: encryption.encrypt(req.key_id, req.plaintext, req.algorithm))


@app.post("/decrypt")
@swag_from({
    "tags": ["Encryption"],
    "summary": "Decrypt a ciphertext with the key corresponding to given key ID",
    "parameters": [
        {
            "name": "body",
            "in": "body",
            "schema": DecryptionRequest.model_json_schema(),
            "required": True
        }
    ],
    "responses": {
        "200": {
            "description": "Successfully decrypted plaintext",
            "schema": DecryptionResponse.model_json_schema()
        },
        "400": {
            "description": "Invalid request",
            "schema": ErrorResponse.model_json_schema()
        }
    }
})
def decrypt():
    return handle_request(DecryptionRequest, lambda req: encryption.decrypt(req.key_id, req.ciphertext, req.algorithm))


@app.post("/generate-hash")
@swag_from({
    "tags": ["Hashing"],
    "summary": "Hash a message",
    "parameters": [
        {
            "name": "body",
            "in": "body",
            "schema": HashRequest.model_json_schema(),
            "required": True
        }
    ],
    "responses": {
        "200": {
            "description": "Successfully generated hash",
            "schema": HashResponse.model_json_schema()
        },
        "400": {
            "description": "Invalid request",
            "schema": ErrorResponse.model_json_schema()
        }
    }
})
def generate_hash():
    return handle_request(HashRequest, lambda req: hashing.generate_hash(req.data, req.algorithm))


@app.post("/verify-hash")
@swag_from({
    "tags": ["Hashing"],
    "summary": "Verify that the hash of a message matches with the given hash",
    "parameters": [
        {
            "name": "body",
            "in": "body",
            "schema": VerifyHashRequest.model_json_schema(),
            "required": True
        }
    ],
    "responses": {
        "200": {
            "description": "Results of hash verification",
            "schema": VerifyHashResponse.model_json_schema()
        },
        "400": {
            "description": "Invalid request",
            "schema": ErrorResponse.model_json_schema()
        }
    }
})
def verify_hash():
    return handle_request(VerifyHashRequest, lambda req: hashing.verify_hash(req.data, req.algorithm, req.hash_value))


# Default endpoint
@app.get("/")
def home():
    return (
        "<h2>Encryption and Hashing API</h2>"
        "<p>Visit the <a href='/apidocs/'>API Documentation</a> for usage details.</p>"
    )


