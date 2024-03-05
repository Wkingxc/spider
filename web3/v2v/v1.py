import json
import requests
import random
from flask import Flask, request
from tools.utils import *
from tools.key_gen import *

# 生成用于注册过程的公私钥
(reg_pubkey, reg_privkey) = rsa.newkeys(2048)

# 对(V_ID+salt)进行hash，生成v_id
V_ID = "1001"
salt = "1234567890"
v_pubkey = None
v_privkey = None
certificate = None

v2v_info = {}

rsu_pubkey = None


app = Flask(__name__)

# 第一阶段，v2接收v1的请求
@app.route('/auth', methods=['POST'])
def v2v_auth():
    global v_id, rsu_pubkey
    data1 = request.json['data']
    v2_id = v_id
    data2 = {
        "data1": data1,
        "signature": request.json['signature'],
        "v2_id": v2_id
    }
    # 用rsa加密data2,发送给rsu
    aes_key = get_random_bytes(16)
    cipher_text, key_and_nonce = encrypt_data(data2, rsu_pubkey, v_privkey, aes_key)
    response = requests.post('http://127.0.0.1:8001/v2v_auth',json=
                             {"encrypted_data": cipher_text.hex(), 
                              "key_and_nonce": key_and_nonce})
    if response.status_code != 200:
        return 201

    res = response.json()
    encrypted_data = bytes.fromhex(res['encrypted_data'])
    nonce = bytes.fromhex(res['key_and_nonce']['nonce'])
    data, signature = decrypt_data(encrypted_data, aes_key, nonce)
    if not verify_signature(data, signature, rsu_pubkey):
        return {'res': '验证rsu的签名失败'}, 201
    if data['R2']['message'] == 1:
        return {'res': 'RSU验证V1 V2失败'}, 201
    
    # 保存i的公钥和会话密钥
    # 生成临时会话密钥
    session_key = get_random_bytes(16)
    v1_id = data1['v_id']
    v1_pubkey = rsa.PublicKey.load_pkcs1(request.json['i_pubkey'].encode())
    if v1_id not in v2v_info:
        v2v_info[v1_id] = {}
    v2v_info[v1_id]['pubkey'] = v1_pubkey
    v2v_info[v1_id]['session_key'] = session_key

    
    r4 = str(random.randint(10000000,99999999))
    v2v_info[v1_id]['r4'] = r4
    cipher1 = AES.new(session_key, AES.MODE_EAX)
    nonce1 = cipher1.nonce
    en_r4 = cipher1.encrypt(r4.encode())
    data_to_send = {
        "v_id": v2_id,
        "session_key": session_key.hex(),
        "nonce1": nonce1.hex(),
        "timestamp": time.time(),
        "r4": en_r4.hex(),
    }
    cipher_text, key_and_nonce = encrypt_data(data_to_send, v1_pubkey, v_privkey, aes_key)

    return {"encrypted_data": cipher_text.hex(),
            "key_and_nonce": key_and_nonce}, 200

# 第二阶段，i接收rsu发来的j的v_id和公钥
@app.route('/auth2', methods=['POST'])
def auth2():
    encrypted_data = bytes.fromhex(request.json['encrypted_data'])
    key_and_nonce = request.json['key_and_nonce']
    aes_key, nonce = get_aes_key_and_nonce(key_and_nonce, v_privkey)
    data, signature = decrypt_data(encrypted_data, aes_key, nonce)
    if not verify_signature(data, signature, rsu_pubkey):
        return False
    # 保存j的公钥
    j_id = data['v_id']
    if j_id not in v2v_info:
        v2v_info[j_id] = {}
    v2v_info[j_id]['pubkey'] = rsa.PublicKey.load_pkcs1(data['pubkey'].encode())
    return "ok", 200

# 第三阶段，j确认i已经获得协商的对称密钥
@app.route('/auth3', methods=['POST'])
def auth3():
    data = request.json['data']
    en_message = bytes.fromhex(data['message'])
    i_id = request.json['v_id']
    nonce2 = bytes.fromhex(data['nonce2'])
    if not validate_timestamp(data['timestamp']):
        return 202
    
    session_key = v2v_info[i_id]['session_key']
    cipher = AES.new(session_key, AES.MODE_EAX, nonce2)
    m_with_sign = cipher.decrypt(en_message).decode()
    message = m_with_sign[:-256]
    sign_m = bytes.fromhex(m_with_sign[-256:])
    try:
        rsa.verify(message.encode(), sign_m, v2v_info[i_id]['pubkey'])
        print("验证成功")
    except rsa.VerificationError:
        print("验证失败")
        return {"res": "rsa签名验证失败"}, 201
    
    r4 = message[0:8]
    if r4 != v2v_info[i_id]['r4']:
        return {"res": "r4验证失败"}, 201
    info = message[8:-8]
    print(f'v2收到消息：{info}')
    return {"res": "认证成功"}, 200


# vi发起认证
def start_auth(v_id, v_privkey, port):
    data1 = {
        "v_id": v_id,
        "timestamp": time.time()
    }
    signature = sign_data(data1, v_privkey)
    j_url = f'http://127.0.0.1:{port}'
    response = requests.post(f'{j_url}/auth', json=
                             {"data": data1, 
                              "signature": signature.hex(),
                              "i_pubkey": v_pubkey.save_pkcs1().decode()})
    if response.status_code != 200:
        return {"res": "第一阶段认证失败"}, 201
    
    res = response.json()
    encrypted_data = bytes.fromhex(res['encrypted_data'])
    aes_key, nonce = get_aes_key_and_nonce(res['key_and_nonce'], v_privkey)
    data, signature = decrypt_data(encrypted_data, aes_key, nonce)
    j_id = data['v_id']
    if not v2v_info[j_id]['pubkey']:
        return {"res": "j的公钥未接收到"}, 201
    
    # i要先接收到RSU发来的j的公钥
    j_pubkey = v2v_info[j_id]['pubkey']
    if not verify_signature(data, signature, j_pubkey):
        return {"res": "j的签名验证失败"}, 201
    if not validate_timestamp(data['timestamp']):
        return 202
    
    # 保存session_key
    session_key = bytes.fromhex(data['session_key'])
    v2v_info[j_id]['session_key'] = session_key
    nonce1 = bytes.fromhex(data['nonce1'])
    cipher1 = AES.new(v2v_info[j_id]['session_key'], AES.MODE_EAX, nonce1)

    r4 = cipher1.decrypt(bytes.fromhex(data['r4'])).decode()
    r5 = str(random.randint(10000000,99999999))
    message = f'{r4}good6666{r5}'
    sign_m = rsa.sign(message.encode(), v_privkey, 'SHA-256').hex()
    m_with_sign = message + sign_m

    cipher2 = AES.new(session_key, AES.MODE_EAX)
    nonce2 = cipher2.nonce
    en_message = cipher2.encrypt(m_with_sign.encode())

    data_to_send = {
        "message": en_message.hex(),
        "nonce2": nonce2.hex(),
        "timestamp": time.time(),
    }
    # 第三阶段，i确认j已经获得协商的对称密钥
    response = requests.post(f'{j_url}/auth3', json={
                            "v_id": v_id,
                            "data": data_to_send,})
    if response.status_code != 200:
        return {"res": "第三阶段认证失败"}, 201
    return {"res": "认证成功"}, 200
    
# 用rsu公钥和v_id注册
def register(rsu_pubkey, v_id):
    # 将reg_pubkey和v_id组成数据附上时间戳并用RSU的公钥签名
    data_to_send = {
        "pubkey": reg_pubkey.save_pkcs1().decode(),
        "v_id": v_id,
        "timestamp": time.time()
    }
    # 生成AES密钥和nonce
    aes_key = get_random_bytes(24)  # AES-192 requires a 24-byte key
    cipher_text, key_and_nonce = encrypt_data(data_to_send, rsu_pubkey, reg_privkey, aes_key)
    response = requests.post('http://127.0.0.1:8001/register',json=
                             {"encrypted_data": cipher_text.hex(), 
                              "key_and_nonce": key_and_nonce})

    if response.status_code != 200:
        return False
    
    response =  response.json()
    encrypted_data = bytes.fromhex(response['encrypted_data'])
    nonce = bytes.fromhex(response['key_and_nonce']['nonce'])
    data, signature = decrypt_data(encrypted_data, aes_key, nonce)
    # 验证签名
    if not verify_signature(data, signature, rsu_pubkey):
        print("Signature verification failed")
        return False

    # 保存用于通信的公私钥和证书
    privkey = rsa.PrivateKey.load_pkcs1(data['privkey'].encode())
    certificate = data['certificate']
    return privkey, certificate

# 请求更新公钥
def request_key_update(rsu_pubkey, v_privkey, v_id):
    data_to_send = {
        "v_id": v_id,
        "timestamp": time.time()
    }
    aes_key = get_random_bytes(16)
    cipher_text, key_and_nonce = encrypt_data(data_to_send, rsu_pubkey, v_privkey, aes_key)
    response = requests.post('http://127.0.0.1:8001/key_update',json=
                             {"encrypted_data": cipher_text.hex(), 
                              "key_and_nonce": key_and_nonce})
    if response.status_code != 200:
        return False
    response =  response.json()
    encrypted_data = bytes.fromhex(response['encrypted_data'])
    nonce = bytes.fromhex(response['key_and_nonce']['nonce'])
    data, signature = decrypt_data(encrypted_data, aes_key, nonce)
    # 验证签名
    if not verify_signature(data, signature, rsu_pubkey):
        print("Signature verification failed")
        return False
    
    # 保存用于通信的公私钥和证书
    privkey = rsa.PrivateKey.load_pkcs1(data['privkey'].encode())
    certificate = data['certificate']
    return privkey, certificate


# 用户命令接口
@app.route('/c', methods=['GET'])
def user_command():
    global v_pubkey, v_privkey, certificate,v_id
    c = request.args.get('c')
    if c == '0':
        if v_privkey:
            data = {
                'cert': certificate,
                'privkey': v_privkey.save_pkcs1().decode(),
            }
            return data,200
        else:
            return {"res": "NULL"},200
        
    elif c == '1':
        v_privkey, certificate = register(rsu_pubkey, v_id)            
        v_pubkey = rsa.PublicKey.load_pkcs1(certificate['pubkey'].encode())
        if check_pri_pub_key(v_pubkey, v_privkey):
            return {'res': "证书注册成功，验证通过！"}, 200

    elif c == '2':
        port = request.args.get('port')
        res = start_auth(v_id, v_privkey, port)
        return res
    

if __name__ == "__main__":
    v_id = gen_v_id(V_ID, salt)
    with open('rsu_public_key.pem', mode='rb') as pub_file:
        rsu_pubkey = rsa.PublicKey.load_pkcs1(pub_file.read())
    # v_pubkey, v_privkey = v_load()
    app.run(debug=True, threaded=True, port=7001)
    