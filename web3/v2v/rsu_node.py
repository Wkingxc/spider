import argparse
from Crypto.Cipher import AES
import rsa
# import json

from flask import Flask, request

from tools.utils import *
from tools.block import *


app = Flask(__name__)

# 保存v_id和临时公钥的映射
v_id_to_pubkey = {}

RSU_PUBLIC_KEY_FILE = "rsu_public_key.pem"
RSU_PRIVATE_KEY_FILE = "rsu_private_key.pem"

with open(RSU_PUBLIC_KEY_FILE, mode='rb') as pub_file:
    rsu_pubkey = rsa.PublicKey.load_pkcs1(pub_file.read())
with open(RSU_PRIVATE_KEY_FILE, mode='rb') as priv_file:
    rsu_privkey = rsa.PrivateKey.load_pkcs1(priv_file.read())


# 节点的区块链副本
blockchain = Blockchain()
blockchain.create_genesis_block()
# 对等节点列表
peers = set()



# 查询证书的接口
@app.route('/search_cert', methods=['POST'])
def search_cert():
    pubkey = request.json['pubkey']
    cert = find_cert(pubkey, blockchain.chain)
    if not cert:
        return {"message": "Certificate not found"}, 400
    return {"certificate": cert, "message": "Certificate found"}, 200


# V向RSU进行注册的接口
@app.route('/register', methods=['POST'])
def V_register():
    encrypted_data = bytes.fromhex(request.json['encrypted_data'])
    key_and_nonce = request.json['key_and_nonce']
    aes_key, nonce = get_aes_key_and_nonce(key_and_nonce, privkey=rsu_privkey)
    data, signature = decrypt_data(encrypted_data, aes_key, nonce)
    # 验证v_id是否已经注册
    # if data['v_id'] in v_id_to_pubkey:
    #     return {"message": "Vehicle already registered"}, 400

    # 验证签名
    reg_pubkey = rsa.PublicKey.load_pkcs1(data['pubkey'].encode())
    if not verify_signature(data, signature, reg_pubkey):
        return {"message": "Signature verification failed"}, 400
    # 验证时间戳
    # if not validate_timestamp(data['timestamp']):
    #     return {"message": "Timestamp verification failed"}, 400

    # 生成公私钥和证书，并保存映射
    data_to_send, certificate = gen_vkey_cert(v_id_to_pubkey, data['v_id'])
    print(f'映射:{v_id_to_pubkey}')
    
    cipher_text, key_and_nonce = encrypt_data(data_to_send, pubkey=reg_pubkey, prikey=rsu_privkey, aes_key=aes_key)

    blockchain.unconfirmed_transactions = certificate

    # 将该交易添加到区块链中
    new_block = blockchain.mine()
    if not new_block:
        return "上链失败"
    else:
        begin = time.time()
        consensus(blockchain,peers) # 通过共识，如果有更长的链，就替换掉当前的链
        end = time.time()
        print(f'共识用时:{end-begin}')

        begin = time.time()
        announce_new_block(new_block,peers)
        end = time.time()
        print(f'广播用时:{end-begin}')

        return {"encrypted_data": cipher_text.hex(), 
                "key_and_nonce": key_and_nonce,
                "message": "Registration successful"}, 200

# V向RSU请求更新公钥的接口
@app.route('/key_update', methods=['POST'])
def V_update_pubkey():
    encrypted_data = bytes.fromhex(request.json['encrypted_data'])
    key_and_nonce = request.json['key_and_nonce']
    aes_key, nonce = get_aes_key_and_nonce(key_and_nonce, privkey=rsu_privkey)
    data, signature = decrypt_data(encrypted_data, aes_key, nonce)

    # 验证签名
    v_pubkey = v_id_to_pubkey[data['v_id']]
    if not verify_signature(data, signature, v_pubkey):
        return {"message": "Signature verification failed"}, 400
    # 验证时间戳
    if not validate_timestamp(data['timestamp']):
        return {"message": "Timestamp verification failed"}, 400
    
    # 生成公私钥和证书，并保存映射
    data_to_send, certificate = gen_vkey_cert(v_id_to_pubkey, data['v_id'])
    print(f'映射:{v_id_to_pubkey}')
    
    cipher_text, key_and_nonce = encrypt_data(data_to_send, pubkey=v_pubkey, prikey=rsu_privkey, aes_key=aes_key)

    blockchain.unconfirmed_transactions = certificate
    # 将该交易添加到区块链中
    new_block = blockchain.mine()    
    if not new_block:
        return "上链失败"
    else:
        begin = time.time()
        consensus(blockchain,peers) # 通过共识，如果有更长的链，就替换掉当前的链
        end = time.time()
        print(f'共识用时:{end-begin}')

        begin = time.time()
        announce_new_block(new_block,peers)
        end = time.time()
        print(f'广播用时:{end-begin}')

        return {"encrypted_data": cipher_text.hex(), 
                "key_and_nonce": key_and_nonce,
                "message": "Update key successful"}, 200
    
# v2v过程的认证接口
@app.route('/v2v_auth', methods=['POST'])
def v2v_auth():
    error = False
    encrypted_data = bytes.fromhex(request.json['encrypted_data'])
    key_and_nonce = request.json['key_and_nonce']
    aes_key, nonce = get_aes_key_and_nonce(key_and_nonce, privkey=rsu_privkey)
    data, signature = decrypt_data(encrypted_data, aes_key, nonce)
    data1_sign = bytes.fromhex(data['signature'])
    # 验证v1、v2证书是否都存在且有效
    v1_id, v2_id = data['data1']['v_id'], data['v2_id']
    cert1, cert2 = find_cert(v_id_to_pubkey[v1_id], blockchain.chain), find_cert(v_id_to_pubkey[v2_id], blockchain.chain)
    v1_pubkey = v_id_to_pubkey[v1_id]
    v2_pubkey = v_id_to_pubkey[v2_id]
    error = (
        v_id_to_pubkey[v1_id] is None or
        v_id_to_pubkey[v2_id] is None or
        not validate_certificate(cert1) or
        not validate_certificate(cert2) or
        not verify_signature(data['data1'], data1_sign, v1_pubkey) or
        not validate_timestamp(data['data1']['timestamp'])
    )
    if error:
        R2 = {"message": 1, "timestamp": time.time()}
    else:
        R2 = {"message": 0, "timestamp": time.time()}
        # 没有错误时，才发给OBUi
        send_to_OBUi(v2_id, v1_pubkey, v2_pubkey)

    data_to_send = {'R2': R2}
    cipher_text, key_and_nonce = encrypt_data(data_to_send, v2_pubkey, rsu_privkey, aes_key=aes_key)
    return {"encrypted_data": cipher_text.hex(),
            "key_and_nonce": key_and_nonce}, 200

# RSU 将 OBUj 的公钥签名 ，并用OBUi公钥加密传给OBUi
def send_to_OBUi(j_id, i_pubkey, j_pubkey):
    data_to_send = {
        "v_id": j_id,
        "pubkey": j_pubkey.save_pkcs1().decode(),
        "timestamp": time.time()
    }
    aes_key = get_random_bytes(16)  # AES-192 requires a 24-byte key
    cipher_text, key_and_nonce = encrypt_data(data_to_send, i_pubkey, rsu_privkey, aes_key)
    OBUi_url = "http://127.0.0.1:7001/auth2"
    response = requests.post(OBUi_url,json=
                             {"encrypted_data": cipher_text.hex(), 
                              "key_and_nonce": key_and_nonce})
    if response.status_code != 200:
        return False


# 返回节点区块链副本的端点。
@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data,
                       "peers": list(peers)})

# 用于将其他人挖掘的区块添加到节点链的端点
@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    block_data = request.get_json()
    block = Block(block_data["index"],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],)


    result = blockchain.add_block(block)
    if not result:
        return "区块验证失败", 400
    
    return f"区块{block.index}已添加到链上", 200

@app.route('/manage_pending_blocks', methods=['GET'])
def manage_pending_blocks():
    blockchain.process_pending_blocks()
    return "处理等待队列中的区块", 200

# 返回公钥映射的数据库
@app.route('/v', methods=['GET'])
def get_v():
    v_id_to_pubkey_str = {k: str(v) for k, v in v_id_to_pubkey.items()}
    return json.dumps(v_id_to_pubkey_str)


def init_peers(peers,port):
    """初始化对等节点列表"""
    begin = 8000
    number = 0
    for i in range(begin,begin+number):
        if i != port:
            peers.add("http://127.0.0.1:"+str(i)+"/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='启动节点')
    parser.add_argument('-p', '--port', type=int, default=8000, help='要使用的端口')
    args = parser.parse_args()
    port = args.port
    init_peers(peers,port)
    print("对等节点列表：", sorted(list(peers)))
    # 在主程序中开始周期性地处理等待队列中的区块
    # manage_pending_blocks_periodically()
    app.run(debug=True, threaded=True, port=port)
