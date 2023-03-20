from flask import Flask, request
from Crypto.Cipher import AES
import base64
import json
import os
import secrets
from Crypto.Hash import HMAC, SHA256

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

    print("encrypted data:", encoded_data) # add this line to print the encrypted data

    response_data = {
        'ciphertext': encoded_data
    }

    return json.dumps(response_data)

@app.route('/verify', methods=['POST'])
def verify():
    plaintext = request.json['plaintext'].encode('utf-8')
    encoded_data = request.json['ciphertext']

    encrypted_data = base64.b64decode(encoded_data.encode('utf-8'))

    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    
    # Verify the authenticity of the ciphertext using HMAC
    hmac_key = key[:16]
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(iv + ciphertext)
    mac = hmac.digest()

    # Compare the provided MAC with the calculated MAC
    provided_mac = request.json['mac']
    if not hmac.compare_digest(mac, base64.b64decode(provided_mac.encode('utf-8'))):
        return json.dumps({'match': False})

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)

    plaintext2 = padded_plaintext.rstrip(b'\0').decode('utf-8')
    
    # Encrypt the plaintext and calculate a new MAC
    iv2 = secrets.token_bytes(AES.block_size)
    padded_plaintext2 = plaintext.encode('utf-8') + b'\0' * (AES.block_size - len(plaintext) % AES.block_size)
    cipher2 = AES.new(key, AES.MODE_CBC, iv2)
    ciphertext2 = cipher2.encrypt(padded_plaintext2)

    hmac2 = HMAC.new(hmac_key, digestmod=SHA256)
    hmac2.update(iv2 + ciphertext2)
    mac2 = hmac2.digest()
    
    # Encode the new ciphertext and MAC and send them back in the response
    encrypted_data2 = iv2 + ciphertext2
    encoded_data2 = base64.b64encode(encrypted_data2).decode('utf-8')
    
    response_data = {
        'match': plaintext == plaintext2,
        'ciphertext': encoded_data2,
        'mac': base64.b64encode(mac2).decode('utf-8')
    }

    return json.dumps(response_data)


if __name__ == '__main__':
    app.run(debug=True)
