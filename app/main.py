# app/main.py
from flask import Blueprint, render_template, redirect, request, send_file, abort, flash, current_app, url_for
from flask_login import login_required, current_user
import os
from .models import File
from .crypto import CryptoManager
from . import db
from datetime import datetime, timedelta
import secrets
from werkzeug.utils import secure_filename

main = Blueprint('main', __name__)

@main.route('/')
@login_required
def index():
    return redirect(url_for('main.dashboard'))

@main.route('/dashboard')
@login_required
def dashboard():
    files = File.query.filter_by(owner_id=current_user.id).order_by(File.created_at.desc()).all()
    return render_template('main/dashboard.html', files=files)

@main.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('main.dashboard'))
        
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('main.dashboard'))
        
    if file:
        filename = secure_filename(file.filename)
        temp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], 'temp', filename)
        os.makedirs(os.path.dirname(temp_path), exist_ok=True)
        
        file.save(temp_path)
        
        try:
            crypto_mgr = CryptoManager()
            encrypted_path = crypto_mgr.encrypt_file(temp_path, current_user.public_key)
            
            new_file = File(
                filename=filename,
                encrypted_path=encrypted_path,
                owner_id=current_user.id
            )
            
            db.session.add(new_file)
            db.session.commit()
            
            flash('File uploaded successfully')
            
        except Exception as e:
            flash(f'Error uploading file: {str(e)}')
        
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        
    return redirect(url_for('main.dashboard'))

@main.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    if file.owner_id != current_user.id:
        abort(403)
        
    try:
        crypto_mgr = CryptoManager()
        decrypted_path = crypto_mgr.decrypt_file(
            file.encrypted_path,
            current_user.private_key,
            request.args.get('password')
        )
        
        return send_file(
            decrypted_path,
            as_attachment=True,
            download_name=file.filename
        )
    except Exception as e:
        flash(f'Error downloading file: {str(e)}')
        return redirect(url_for('main.dashboard'))

@main.route('/share/<int:file_id>')
@login_required
def create_share_link(file_id):
    file = File.query.get_or_404(file_id)
    
    if file.owner_id != current_user.id:
        abort(403)
    
    # Generate temporary link
    file.temporary_link = secrets.token_urlsafe(32)
    file.link_expiry = datetime.utcnow() + timedelta(hours=24)
    
    try:
        db.session.commit()
        return file.temporary_link
    except Exception as e:
        db.session.rollback()
        return str(e), 500

@main.route('/shared/<token>')
def access_shared_file(token):
    file = File.query.filter_by(temporary_link=token).first_or_404()
    
    if file.link_expiry and file.link_expiry < datetime.utcnow():
        abort(404)
    
    try:
        crypto_mgr = CryptoManager()
        decrypted_path = crypto_mgr.decrypt_file(
            file.encrypted_path,
            file.owner.private_key,
            request.args.get('password')
        )
        
        return send_file(
            decrypted_path,
            as_attachment=True,
            download_name=file.filename
        )
    except Exception as e:
        flash(f'Error accessing shared file: {str(e)}')
        return redirect(url_for('main.dashboard'))