from app import db

class SymmetricKey(db.Model):
    # Database model for symmetric keys
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.String, nullable=False)
    key_type = db.Column(db.String(10), nullable=False)
    key_value = db.Column(db.String, nullable=False)  

    def get_value(self):
        # For looking up key
        return self.key_value
    
    def get_response(self):
        # Response for key generation request
        return {"key_id": self.key_id, "key_value": self.key_value}
    

class AsymmetricKey(db.Model):
    # Database model for asymmetric keys
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.String, nullable=False)
    key_type = db.Column(db.String(10), nullable=False)
    key_public = db.Column(db.String, nullable=False)  
    key_private = db.Column(db.String, nullable=False)  

    def get_value(self):
        # For looking up key
        return {
            "private_key": self.key_private,
            "public_key": self.key_public
        }
    
    def get_response(self):
        # Response for key generation request
        return {"key_id": self.key_id, "key_value": self.key_public}


def store_key(key_type, key_id, key_value):
    # Store a given key. key_value is a single value for AES and a dictionary for RSA.
    
    if key_type == "AES":
        new_key = SymmetricKey(
            key_id=key_id,
            key_type=key_type,
            key_value=key_value
        )
    elif key_type == "RSA":
        new_key = AsymmetricKey(
            key_id=key_id,
            key_type=key_type,
            key_public=key_value["public_key"],
            key_private=key_value["private_key"]
        )
    # Insert into the database
    db.session.add(new_key)
    db.session.commit()

    return new_key.get_response()


def get_key(key_type, key_id):
    # Look up key from database
    Key = SymmetricKey if key_type == "AES" else AsymmetricKey

    key = Key.query.filter_by(key_id=key_id, key_type=key_type).first()

    if not key:     # Key does not exist
        return None
    return key.get_value()