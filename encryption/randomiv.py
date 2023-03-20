from flask import Flask, request
from Crypto.Cipher import AES
import base64
import json
import os
import secrets

app = Flask(__name__)

key_str = os.environ.get('ENCRYPTION_KEY')
key = key_str.encode('utf-8')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    plaintext = request.json['plaintext'].encode('utf-8')

    iv = secrets.token_bytes(AES.block_size)

    padded_plaintext = plaintext + b'\0' * (AES.block_size - len(plaintext) % AES.block_size)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(padded_plaintext)

    encrypted_data = iv + ciphertext

    encoded_data = base64.b64encode(encrypted_data).decode('utf-8')

    response_data = {
        'ciphertext': encoded_data
    }

    return json.dumps(response_data)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encoded_data = request.json['ciphertext']

    encrypted_data = base64.b64decode(encoded_data.encode('utf-8'))

    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)

    plaintext = padded_plaintext.rstrip(b'\0').decode('utf-8')

    response_data = {
        'plaintext': plaintext
    }

    return json.dumps(response_data)

if __name__ == '__main__':
    app.run(debug=True)
