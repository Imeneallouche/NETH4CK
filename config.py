# Database connection details
SQLALCHEMY_DATABASE_URI = "sqlite:///your_database.db"      # database
SECRET_KEY = "your_secret_key"                              # secret key

import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'mysecret')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///test.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
