import rsa
import json
import time
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes



"""
    通用函数
"""
# 检测公私钥是否为一对
def check_pri_pub_key(v_pubkey, v_privkey):
    test_data = b'This is some test data'
    encrypted_data = rsa.encrypt(test_data, v_pubkey)
    decrypted_data = rsa.decrypt(encrypted_data, v_privkey)
    if decrypted_data == test_data:
        return True
    else:
        return False
    
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


# 用私钥解密出AES密钥和nonce
def get_aes_key_and_nonce(key_and_nonce, privkey):
    nonce = bytes.fromhex(key_and_nonce['nonce'])
    encrypted_key = bytes.fromhex(key_and_nonce['aes_key'])
    aes_key = rsa.decrypt(encrypted_key, privkey)
    return aes_key, nonce

# 利用AES和RSA对json数据混合加密并附上签名
def encrypt_data(data, pubkey, prikey, aes_key):
    # 签名并使用AES加密数据
    signature = sign_data(data, prikey)
    data_to_encrypt = {
        "data": data,
        "signature": signature.hex()
    }
    cipher = AES.new(aes_key, AES.MODE_EAX)
    cipher_text = cipher.encrypt(json.dumps(data_to_encrypt).encode())
    nonce = cipher.nonce
    encrypted_key = rsa.encrypt(aes_key, pubkey)
    # 使用RSA公钥加密AES密钥和nonce
    key_and_nonce = {
        "aes_key": encrypted_key.hex(),
        "nonce": nonce.hex()
    }
    return cipher_text, key_and_nonce 

# 利用AES解密出json数据和签名
def decrypt_data(encrypted_data, aes_key, nonce):
    # 使用AES密钥和nonce解密数据
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt(encrypted_data)
    try:
        decrypted_data = json.loads(decrypted_data.decode())
    except UnicodeDecodeError:
        return False
    data = decrypted_data['data']
    signature = bytes.fromhex(decrypted_data['signature'])
    return data, signature


"""
    V节点函数
"""
def gen_v_id(V_ID, salt):
    return sha256((V_ID + salt).encode()).hexdigest()



"""
    RSU节点函数
"""
# 检测证书1.是否被吊销 2.是否过期
def validate_certificate(certificate):
    return not certificate['revoked'] and time.time() < certificate['validity']

# 生成车辆的证书和通信时的临时公私钥
def gen_vkey_cert(v_id_to_pubkey, v_id):
    begin = time.time()
    (v_pubkey, v_privkey) = rsa.newkeys(1024)
    end = time.time()
    print(f'生成公私钥用时:{end-begin}')

    # 保存v_id和临时公钥字节流的映射
    v_id_to_pubkey[v_id] = v_pubkey

    # 生成车辆的证书
    certificate = {
        "pubkey": v_pubkey.save_pkcs1().decode(),
        # 证书的有效期
        "validity": time.time() + 60 * 5,
        "revoked": False
    }
    # 将用于通信的私钥、证书附上时间戳组成数据
    data_to_send = {
        "privkey": v_privkey.save_pkcs1().decode(),
        "certificate": certificate,
        "timestamp": time.time()
    }
    return data_to_send, certificate
    
# 查找车辆的证书
def find_cert(pubkey, chain):
    pubkey = pubkey.save_pkcs1().decode()
    for block in reversed(chain):
        if block.transactions['pubkey'] == pubkey:
            if validate_certificate(block.transactions):
                return block.transactions
            else:
                break
    return None

