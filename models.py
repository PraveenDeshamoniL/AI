
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(200))
    otp_secret = db.Column(db.String(16))
    is_admin = db.Column(db.Boolean, default=False)
    scans = db.relationship('ScanLog', backref='user', lazy=True)

class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500))
    malware_result = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
