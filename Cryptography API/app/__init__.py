from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flasgger import Swagger

db = SQLAlchemy()

app = Flask(__name__)

# Configure SQLite database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///keys.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)  # Initialize database after app is created

# Initialize swagger
app.config['SWAGGER'] = {
    'title': 'Encryption and Hashing API',
    'uiversion': 3
}
swagger = Swagger(app)  

# Create database tables
with app.app_context():
    from app.database import SymmetricKey, AsymmetricKey
    db.create_all()  # Ensures tables are created

from app import routes