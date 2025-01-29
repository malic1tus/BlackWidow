# app/models.py
from . import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)
    files = db.relationship('File', backref='owner', lazy=True)

class File(db.Model):
    __tablename__ = 'file'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_path = db.Column(db.String(255), nullable=False)
    file_key = db.Column(db.Text)  # Encrypted AES key
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    temporary_link = db.Column(db.String(255), unique=True, nullable=True)
    link_expiry = db.Column(db.DateTime, nullable=True)