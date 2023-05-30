from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)


def encrypt_with_rsa(data):
  public_key_path = 'public_key.pem'
  # Load the public key from the given file path
  with open(public_key_path, 'rb') as key_file:
    pem_data = key_file.read()
    public_key = RSA.import_key(pem_data)

  cipher = PKCS1_v1_5.new(public_key)
  encrypted_data = cipher.encrypt(data.encode('utf-8'))
  encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
  return encoded_data


def encrypt_by_symmetric_key(json_data, decrypted_sek):
  sek_byte = base64.b64decode(decrypted_sek)
  aes_key = AES.new(sek_byte, AES.MODE_ECB)
  try:
    padded_data = pad(json_data.encode(), AES.block_size)
    encrypted_bytes = aes_key.encrypt(padded_data)
    encrypted_json = base64.b64encode(encrypted_bytes).decode()
    return encrypted_json
  except Exception as e:
    return f"Exception {e}"


def decrypt_sek_with_appkey(encrypted_sek, base64_appkey):
  appkey = base64.b64decode(base64_appkey)
  encrypted_sek = base64.b64decode(encrypted_sek)
  cipher = AES.new(appkey, AES.MODE_ECB)
  decrypted_sek = cipher.decrypt(encrypted_sek)
  unpadded_sek = unpad(decrypted_sek, AES.block_size)
  base64_decoded_sek = base64.b64encode(unpadded_sek).decode('utf-8')
  return base64_decoded_sek


@app.route('/encryptrsa', methods=['POST'])
def encrypt_routeRSA():
  data = request.json['data']

  encoded_data = encrypt_with_rsa(data)

  response = {
    'encrypted_data': encoded_data,
  }
  return jsonify(response)


@app.route('/encryptaes', methods=['POST'])
def encrypt_route():
  data = request.json['data']
  appkey = request.json['appkey']

  encrypted_Data = encrypt_by_symmetric_key(data, appkey)

  response = {'encrypted_Data': encrypted_Data}
  return jsonify(response)


@app.route('/decryptsek', methods=['POST'])
def decrypt_route():
  encrypted_sek = request.json['encrypted_sek']
  appkey = request.json['appkey']

  decrypted_sek = decrypt_sek_with_appkey(encrypted_sek, appkey)

  response = {'decrypted_sek': decrypted_sek}
  return jsonify(response)


if __name__ == '__main__':
  app.run()
