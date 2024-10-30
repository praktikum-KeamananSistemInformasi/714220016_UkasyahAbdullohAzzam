from flask import Flask, request, render_template
from Crypto.Cipher import AES, DES, DES3, Blowfish, ChaCha20, Salsa20
from Crypto.Random import get_random_bytes
import base64

app = Flask(__name__)

# AES encryption/decryption
def encrypt_aes(plain_text, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_aes(cipher_text, key):
    raw_data = base64.b64decode(cipher_text)
    nonce = raw_data[:16]
    ciphertext = raw_data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plain_text = cipher.decrypt(ciphertext)
    return plain_text.decode('utf-8')

# DES encryption/decryption
def encrypt_des(plain_text, key):
    cipher = DES.new(key, DES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_des(cipher_text, key):
    raw_data = base64.b64decode(cipher_text)
    nonce = raw_data[:8]
    ciphertext = raw_data[8:]
    cipher = DES.new(key, DES.MODE_EAX, nonce=nonce)
    plain_text = cipher.decrypt(ciphertext)
    return plain_text.decode('utf-8')

# 3DES encryption/decryption
def encrypt_3des(plain_text, key):
    cipher = DES3.new(key, DES3.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_3des(cipher_text, key):
    raw_data = base64.b64decode(cipher_text)
    nonce = raw_data[:16]
    ciphertext = raw_data[16:]
    cipher = DES3.new(key, DES3.MODE_EAX, nonce=nonce)
    plain_text = cipher.decrypt(ciphertext)
    return plain_text.decode('utf-8')

# Blowfish encryption/decryption
def encrypt_blowfish(plain_text, key):
    cipher = Blowfish.new(key, Blowfish.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_blowfish(cipher_text, key):
    raw_data = base64.b64decode(cipher_text)
    nonce = raw_data[:8]
    ciphertext = raw_data[8:]
    cipher = Blowfish.new(key, Blowfish.MODE_EAX, nonce=nonce)
    plain_text = cipher.decrypt(ciphertext)
    return plain_text.decode('utf-8')

# ChaCha20 encryption/decryption
def encrypt_chacha20(plain_text, key):
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(plain_text.encode('utf-8'))
    return base64.b64encode(cipher.nonce + ciphertext).decode('utf-8')

def decrypt_chacha20(cipher_text, key):
    raw_data = base64.b64decode(cipher_text)
    nonce = raw_data[:8]
    ciphertext = raw_data[8:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plain_text = cipher.decrypt(ciphertext)
    return plain_text.decode('utf-8')

# Salsa20 encryption/decryption
def encrypt_salsa20(plain_text, key):
    cipher = Salsa20.new(key=key)
    ciphertext = cipher.encrypt(plain_text.encode('utf-8'))
    return base64.b64encode(cipher.nonce + ciphertext).decode('utf-8')

def decrypt_salsa20(cipher_text, key):
    raw_data = base64.b64decode(cipher_text)
    nonce = raw_data[:8]
    ciphertext = raw_data[8:]
    cipher = Salsa20.new(key=key, nonce=nonce)
    plain_text = cipher.decrypt(ciphertext)
    return plain_text.decode('utf-8')

# Random keys for each algorithm
key_aes = get_random_bytes(32)  # 256-bit for AES
key_des = get_random_bytes(8)   # 64-bit for DES
key_3des = get_random_bytes(24) # 192-bit for 3DES
key_blowfish = get_random_bytes(16) # 128-bit for Blowfish
key_chacha20 = get_random_bytes(32) # 256-bit for ChaCha20
key_salsa20 = get_random_bytes(32)  # 256-bit for Salsa20

@app.route('/')
def index():
    return render_template('index.html', result="")

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    plain_text = request.form.get('plain_text')
    algorithm = request.form.get('algorithm')

    if algorithm == "AES":
        encrypted_text = encrypt_aes(plain_text, key_aes)
        result = f"Encrypted: {encrypted_text}"
    elif algorithm == "DES":
        encrypted_text = encrypt_des(plain_text, key_des)
        result = f"Encrypted: {encrypted_text}"
    elif algorithm == "3DES":
        encrypted_text = encrypt_3des(plain_text, key_3des)
        result = f"Encrypted: {encrypted_text}"
    elif algorithm == "Blowfish":
        encrypted_text = encrypt_blowfish(plain_text, key_blowfish)
        result = f"Encrypted: {encrypted_text}"
    elif algorithm == "ChaCha20":
        encrypted_text = encrypt_chacha20(plain_text, key_chacha20)
        result = f"Encrypted: {encrypted_text}"
    elif algorithm == "Salsa20":
        encrypted_text = encrypt_salsa20(plain_text, key_salsa20)
    else:
        encrypted_text = "Unsupported algorithm"

    result = f"Encrypted: {encrypted_text}"
    return render_template('index.html', result=result, algorithm=algorithm)

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    cipher_text = request.form.get('cipher_text')
    algorithm = request.form.get('algorithm')

    try:
        if algorithm == "AES":
            decrypted_text = decrypt_aes(cipher_text, key_aes)
            result = f"Decrypted: {decrypted_text}"
        elif algorithm == "DES":
            decrypted_text = decrypt_des(cipher_text, key_des)
            result = f"Decrypted: {decrypted_text}"
        elif algorithm == "3DES":
            decrypted_text = decrypt_3des(cipher_text, key_3des)
            result = f"Decrypted: {decrypted_text}"
        elif algorithm == "Blowfish":
            decrypted_text = decrypt_blowfish(cipher_text, key_blowfish)
            result = f"Decrypted: {decrypted_text}"
        elif algorithm == "ChaCha20":
            decrypted_text = decrypt_chacha20(cipher_text, key_chacha20)
            result = f"Decrypted: {decrypted_text}"
        elif algorithm == "Salsa20":
            decrypted_text = decrypt_salsa20(cipher_text, key_salsa20)
            result = f"Decrypted: {decrypted_text}"    
        else:
            decrypted_text = "Unsupported algorithm"
    except Exception as e:
        decrypted_text = f"Error: {str(e)}"

    result = f"Decrypted: {decrypted_text}"
    return render_template('index.html', result=result, algorithm=algorithm)

if __name__ == '__main__':
    app.run(debug=True)
