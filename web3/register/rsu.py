from flask import Flask, request
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import rsa
import time
import json

app = Flask(__name__)

# 保存v_id和临时公钥的映射
v_id_to_pubkey = {}

RSU_PUBLIC_KEY_FILE = "rsu_public_key.pem"
RSU_PRIVATE_KEY_FILE = "rsu_private_key.pem"

with open(RSU_PUBLIC_KEY_FILE, mode='rb') as pub_file:
    rsu_pubkey = rsa.PublicKey.load_pkcs1(pub_file.read())
with open(RSU_PRIVATE_KEY_FILE, mode='rb') as priv_file:
    rsu_privkey = rsa.PrivateKey.load_pkcs1(priv_file.read())

# 对json数据进行私钥签名
def sign_data(data, privkey):
    # 将数据转换为字符串并编码
    data_str = json.dumps(data).encode()
    # 使用私钥签名数据
    signature = rsa.sign(data_str, privkey, 'SHA-256')
    return signature

# 对json数据进行签名验证
def verify_signature(data, signature, pubkey):
    # 计算数据的哈希值
    data_str = json.dumps(data).encode()
    try:
        # 验证签名
        rsa.verify(data_str, signature, pubkey)
        print("Signature is valid")
        return True
    except rsa.VerificationError:
        return False
    
def validate_timestamp(timestamp):
    return time.time() - timestamp < 60 * 5

# 检测证书1.是否被吊销 2.是否过期
def validate_certificate(certificate):
    return not certificate['revoked'] and time.time() < certificate['validity']


@app.route('/register', methods=['POST'])
def register():
    encrypted_data = bytes.fromhex(request.json['encrypted_data'])
    encrypted_key_and_nonce = bytes.fromhex(request.json['encrypted_key_and_nonce'])

    # 解密AES密钥和nonce
    key_and_nonce = rsa.decrypt(encrypted_key_and_nonce, rsu_privkey)
    key_and_nonce = json.loads(key_and_nonce.decode())
    aes_key = bytes.fromhex(key_and_nonce['aes_key'])
    nonce = bytes.fromhex(key_and_nonce['nonce'])

    # 使用AES密钥和nonce解密数据
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt(encrypted_data)
    try:
        decrypted_data = json.loads(decrypted_data.decode())
    except UnicodeDecodeError:
        return {"message": "Decryption failed. Invalid AES key or data."}

    data = decrypted_data['data']
    # 验证v_id是否已经注册
    # if data['v_id'] in v_id_to_pubkey:
    #     return {"message": "Vehicle already registered"}, 400
    signature = bytes.fromhex(decrypted_data['signature'])

    # 验证签名
    r_pubkey = rsa.PublicKey.load_pkcs1(data['pubkey'].encode())
    if not verify_signature(data, signature, r_pubkey):
        return {"message": "Signature verification failed"}, 400
    # 验证时间戳
    # if not validate_timestamp(data['timestamp']):
    #     return {"message": "Timestamp verification failed"}, 400

    # 生成车辆用于通信过程的临时公私钥
    begin = time.time()
    (pubkey, privkey) = rsa.newkeys(1024)
    end = time.time()
    print(f'生成公私钥用时:{end-begin}')

    # 保存v_id和临时公钥的映射
    v_id_to_pubkey[data['v_id']] = pubkey.save_pkcs1().decode()
    print(f'映射:{v_id_to_pubkey}')

    # 生成车辆的证书
    certificate = {
        "pubkey": pubkey.save_pkcs1().decode(),
        # 证书的有效期
        "validity": time.time() + 60 * 5,
        "revoked": False
    }
    # 将用于通信的私钥、证书附上时间戳组成数据
    data_to_send = {
        "privkey": privkey.save_pkcs1().decode(),
        "certificate": certificate,
        "timestamp": time.time()
    }
    # 签名
    signature = sign_data(data_to_send, rsu_privkey)

    # 将签名和数据一起加密
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    data_to_encrypt = {
        "data": data_to_send,
        "signature": signature.hex()
    }
    cipher_text = cipher.encrypt(json.dumps(data_to_encrypt).encode())

    return {"encrypted_data": cipher_text.hex(), "message": "Registration successful"}, 200

if __name__ == '__main__':
    app.run(debug=True)