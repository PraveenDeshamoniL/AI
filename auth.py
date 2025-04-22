
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required
from models import db, User
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        otp = request.form['otp']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            totp = pyotp.TOTP(user.otp_secret)
            if totp.verify(otp):
                login_user(user)
                return redirect(url_for('index'))
            flash('Invalid OTP', 'danger')
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        otp_secret = pyotp.random_base32()
        hashed_pw = generate_password_hash(password)
        user = User(email=email, password=hashed_pw, otp_secret=otp_secret, is_admin=False)
        db.session.add(user)
        db.session.commit()
        flash(f"Register successful! OTP Secret: {otp_secret}", 'info')
        return redirect(url_for('auth.login'))
    return render_template('register.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
