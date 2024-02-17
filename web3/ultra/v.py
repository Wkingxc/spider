import rsa
import requests
import time
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from tools.utils import *

# 生成用于注册过程的公私钥
(r_pubkey, r_privkey) = rsa.newkeys(2048)

# 通信过程的公私钥
v_pubkey = None
v_privkey = None

# 对(V_ID+salt)进行hash，生成v_id
V_ID = "1001"
salt = "TA_assigned_salt"
aes_key = None
nonce = None 

# 用rsu公钥和v_id注册
def register(rsu_pubkey, v_id):
    # 将r_pubkey和v_id组成数据附上时间戳并用RSU的公钥签名
    timestamp = time.time()
    data_to_send = {
        "pubkey": r_pubkey.save_pkcs1().decode(),
        "v_id": v_id,
        "timestamp": timestamp
    }

    # 签名
    signature = sign_data(data_to_send, r_privkey)
    # 生成随机AES密钥
    global aes_key, nonce
    aes_key = get_random_bytes(24)  # AES-192 requires a 24-byte key
    cipher = AES.new(aes_key, AES.MODE_EAX)
    nonce = cipher.nonce
    data_to_encrypt = {
        "data": data_to_send,
        "signature": signature.hex()
    }
    cipher_text = cipher.encrypt(json.dumps(data_to_encrypt).encode())

    # 创建一个包含AES密钥和nonce的字典，然后将这个字典转换为JSON字符串
    key_and_nonce = json.dumps({"aes_key": aes_key.hex(), "nonce": cipher.nonce.hex()})

    # 使用RSA公钥加密AES密钥和nonce
    encrypted_key_and_nonce = rsa.encrypt(key_and_nonce.encode(), rsu_pubkey)
    # print(cipher_text.hex(),end = '\n\n\n')
    # print(encrypted_key_and_nonce.hex())
    # 发送给RSU
    response = requests.post('http://localhost:8000/register',json=
                             {"encrypted_data": cipher_text.hex(), 
                              "encrypted_key_and_nonce": encrypted_key_and_nonce.hex()})

    if response.status_code != 200:
        return False
    return response.json()

# 注册阶段处理RSU的响应
def handle_response(rsu_pubkey, response):
    encrypted_data = bytes.fromhex(response['encrypted_data'])

    # 解密数据
    global aes_key, nonce
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt(encrypted_data)
    try:
        decrypted_data = json.loads(decrypted_data.decode())
    except UnicodeDecodeError:
        return False
    
    data = decrypted_data['data']
    signature = bytes.fromhex(decrypted_data['signature'])

    # 验证签名
    if not verify_signature(data, signature, rsu_pubkey):
        return False

    # 保存用于通信的公私钥和证书
    privkey = rsa.PrivateKey.load_pkcs1(data['privkey'].encode())
    certificate = data['certificate']

    return privkey, certificate

# 请求更新公钥
def request_key_update():
    pass


if __name__ == "__main__":
    v_id = gen_v_id(V_ID, salt)
    with open('rsu_public_key.pem', mode='rb') as pub_file:
        rsu_pubkey = rsa.PublicKey.load_pkcs1(pub_file.read())
    while True:
        command = input('请输入指令：')
        if command == '1':
            res = register(rsu_pubkey, v_id)
            if not res:
                print("Registration failed")
                exit(1)
            v_privkey, certificate = handle_response(rsu_pubkey, res)
            v_pubkey = rsa.PublicKey.load_pkcs1(certificate['pubkey'].encode())
            print(check_pri_pub_key(v_pubkey, v_privkey))

