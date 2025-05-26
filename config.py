import os

# Secret key for session management
SECRET_KEY = os.urandom(24)

# Database configuration
basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'suggestions.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False