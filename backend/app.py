from fastapi import FastAPI, UploadFile, File, HTTPException, Form
import os
import shutil
import pymysql
from nyxcrypta import NyxCrypta, SecurityLevel, KeyFormat

# Initialisation de FastAPI
app = FastAPI()

# Connexion MySQL
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "password",
    "database": "phantomvault"
}
conn = pymysql.connect(**DB_CONFIG)

# Chemin des clés et des fichiers
KEYS_DIR = "./keys"
FILES_DIR = "./files"
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(FILES_DIR, exist_ok=True)

# Initialisation de NyxCrypta avec sécurité maximale
nx = NyxCrypta(SecurityLevel.PARANOID)

# Génération des clés au démarrage
if not os.path.exists(f"{KEYS_DIR}/private_key.pem"):
    nx.save_keys(KEYS_DIR, "super_secure_password", KeyFormat.PEM)


@app.post("/encrypt-file/")
async def encrypt_file(file: UploadFile = File(...)):
    """Chiffre un fichier et le stocke dans FILES_DIR"""
    file_path = os.path.join(FILES_DIR, file.filename)
    enc_file_path = file_path + ".nyx"

    # Sauvegarde du fichier temporaire
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Chiffrement avec NyxCrypta
    pub_key_path = f"{KEYS_DIR}/public_key.pem"
    nx.encrypt_file(file_path, enc_file_path, pub_key_path)
    os.remove(file_path)  # Supprime le fichier non chiffré

    # Enregistrement en base de données
    try:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO files (name, dir) VALUES (%s, %s)", (file.filename, enc_file_path))
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"message": "Fichier chiffré", "file": enc_file_path}


@app.post("/decrypt-file/")
async def decrypt_file(file_name: str = Form(...), password: str = Form(...)):
    """Déchiffre un fichier et le retourne"""
    enc_file_path = os.path.join(FILES_DIR, file_name + ".nyx")
    dec_file_path = os.path.join(FILES_DIR, "decrypted_" + file_name)

    if not os.path.exists(enc_file_path):
        raise HTTPException(status_code=404, detail="Fichier non trouvé")

    # Déchiffrement avec NyxCrypta
    priv_key_path = f"{KEYS_DIR}/private_key.pem"
    try:
        nx.decrypt_file(enc_file_path, dec_file_path, priv_key_path, password)
    except Exception as e:
        raise HTTPException(status_code=403, detail="Échec du déchiffrement")

    return {"message": "Fichier déchiffré", "file": dec_file_path}


@app.post("/generate-share/")
async def generate_share(file_name: str = Form(...), expiration: int = Form(...)):
    """Génère un lien de partage sécurisé"""
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT dir FROM files WHERE name = %s", (file_name,))
            file = cursor.fetchone()
            if not file:
                raise HTTPException(status_code=404, detail="Fichier non trouvé")

            # Génération d'une URL de partage fictive
            share_url = f"http://localhost:8000/download/{file_name}"

            cursor.execute("INSERT INTO shares (dir, date_expiration, url) VALUES (%s, NOW() + INTERVAL %s DAY, %s)",
                           (file[0], expiration, share_url))
        conn.commit()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"message": "Lien généré", "url": share_url}
