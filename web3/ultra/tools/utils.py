import rsa
import json
import time
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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

def gen_v_id(V_ID, salt):
    return sha256((V_ID + salt).encode()).hexdigest()

# 检测证书1.是否被吊销 2.是否过期
def validate_certificate(certificate):
    return not certificate['revoked'] and time.time() < certificate['validity']



# 利用AES和RSA对json数据混合加密并附上签名
def encrypt_data(data, pubkey, prikey):
    """
    参数:
    data (dict): 需要加密的数据。
    pubkey (rsa.key.PublicKey): 用于加密AES密钥和nonce的RSA公钥。
    prikey (rsa.key.PrivateKey): 用于签名数据的RSA私钥。

    返回:
    tuple: 包含两个元素的元组，第一个元素是加密后的数据（bytes），第二个元素是加密后的AES密钥和nonce（bytes）。
    """
    # 生成AES密钥和nonce
    aes_key = get_random_bytes(24)  # AES-192 requires a 24-byte key
    nonce = get_random_bytes(16)
    # 签名并使用AES加密数据
    signature = sign_data(data, prikey)
    data_to_encrypt = {
        "data": data,
        "signature": signature.hex()
    }
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    cipher_text = cipher.encrypt(json.dumps(data_to_encrypt).encode())
    # 使用RSA公钥加密AES密钥和nonce
    key_and_nonce = json.dumps({"aes_key": aes_key.hex(), "nonce": nonce.hex()})
    encrypted_key_and_nonce = rsa.encrypt(key_and_nonce.encode(), pubkey)
    return cipher_text, encrypted_key_and_nonce

# 利用AES和RSA对json数据混合解密并验证签名
def decrypt_data(encrypted_data, encrypted_key_and_nonce, pubkey, prikey):
    """
    参数:
    encrypted_data (bytes): 需要解密的数据，这应该是一个由AES加密的字节串。
    encrypted_key_and_nonce (bytes): 需要解密的AES密钥和nonce，这应该是一个由RSA加密的字节串。
    pubkey (rsa.key.PublicKey): 用于验证数据签名的RSA公钥。
    prikey (rsa.key.PrivateKey): 用于解密AES密钥和nonce的RSA私钥。

    返回:
    dict or bool: 如果解密和验证签名成功，返回解密后的数据（字典）。如果解密失败或验证签名失败，返回False。
    """
    key_and_nonce = rsa.decrypt(encrypted_key_and_nonce, prikey)
    key_and_nonce = json.loads(key_and_nonce.decode())
    aes_key = bytes.fromhex(key_and_nonce['aes_key'])
    nonce = bytes.fromhex(key_and_nonce['nonce'])
    # 使用AES密钥和nonce解密数据
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt(encrypted_data)
    try:
        decrypted_data = json.loads(decrypted_data.decode())
    except UnicodeDecodeError:
        return False
    data = decrypted_data['data']
    signature = bytes.fromhex(decrypted_data['signature'])
    # 验证签名
    if not verify_signature(data, signature, pubkey):
        return False
    return data

