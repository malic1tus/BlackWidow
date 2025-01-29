# app/auth.py
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from .crypto import CryptoManager
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        else:
            flash('Please check your login details and try again.')
            
    return render_template('auth/login.html')

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists')
            return redirect(url_for('auth.signup'))
        
        crypto_mgr = CryptoManager()
        public_key, private_key = crypto_mgr.generate_user_keys(password)
        
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            public_key=public_key,
            private_key=private_key
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully. Please login.')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/signup.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))