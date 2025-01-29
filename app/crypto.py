# app/crypto.py
from nyxcrypta import NyxCrypta, SecurityLevel, KeyFormat
import os
import base64

class CryptoManager:
    def __init__(self, security_level=SecurityLevel.STANDARD):
        self.nx = NyxCrypta(security_level)
    
    def generate_user_keys(self, password):
        """Generate a new key pair for a user"""
        temp_dir = os.path.join(os.getcwd(), 'temp_keys')
        os.makedirs(temp_dir, exist_ok=True)
        
        self.nx.save_keys(temp_dir, password, KeyFormat.PEM)
        
        with open(os.path.join(temp_dir, 'public_key.pem'), 'r') as f:
            public_key = f.read()
        with open(os.path.join(temp_dir, 'private_key.pem'), 'r') as f:
            private_key = f.read()
            
        # Clean up temporary files
        for file in os.listdir(temp_dir):
            os.remove(os.path.join(temp_dir, file))
        os.rmdir(temp_dir)
            
        return public_key, private_key
    
    def encrypt_file(self, file_path, public_key):
        """Encrypt a file and return the encrypted file path and encrypted key"""
        encrypted_file = f"{file_path}.nyx"
        self.nx.encrypt_file(file_path, encrypted_file, public_key)
        return encrypted_file

    def decrypt_file(self, encrypted_file, private_key, password):
        """Decrypt a file and return the decrypted file path"""
        decrypted_file = encrypted_file.replace('.nyx', '_decrypted')
        self.nx.decrypt_file(encrypted_file, decrypted_file, private_key, password)
        return decrypted_file