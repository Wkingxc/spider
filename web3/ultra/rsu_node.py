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


# 返回节点区块链副本的端点。
@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data,
                       "peers": list(peers)})

# V向RSU进行注册的接口
@app.route('/register', methods=['POST'])
def V_register():
    encrypted_data = bytes.fromhex(request.json['encrypted_data'])
    encrypted_key_and_nonce = bytes.fromhex(request.json['encrypted_key_and_nonce'])

    aes_key, nonce = get_aes_key_and_nonce(encrypted_key_and_nonce, privkey=rsu_privkey)
    data, signature = decrypt_data(encrypted_data, aes_key, nonce)
    # 验证v_id是否已经注册
    # if data['v_id'] in v_id_to_pubkey:
    #     return {"message": "Vehicle already registered"}, 400

    # 验证签名
    r_pubkey = rsa.PublicKey.load_pkcs1(data['pubkey'].encode())
    if not verify_signature(data, signature, r_pubkey):
        return {"message": "Signature verification failed"}, 400
    # 验证时间戳
    # if not validate_timestamp(data['timestamp']):
    #     return {"message": "Timestamp verification failed"}, 400

    # 生成车辆用于通信过程的临时公私钥
    begin = time.time()
    (v_pubkey, v_privkey) = rsa.newkeys(1024)
    end = time.time()
    print(f'生成公私钥用时:{end-begin}')

    # 保存v_id和临时公钥的映射
    v_id_to_pubkey[data['v_id']] = v_pubkey.save_pkcs1().decode()
    print(f'映射:{v_id_to_pubkey}')

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
    
    cipher_text, _ = encrypt_data(data_to_send, pubkey=r_pubkey, prikey=rsu_privkey, aes_key=aes_key, nonce=nonce)

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

        return {"encrypted_data": cipher_text.hex(), "message": "Registration successful"}, 200

# V向RSU请求更新公钥的接口
@app.route('/update_pubkey', methods=['POST'])
def V_update_pubkey():
    pass
    

# 用于将其他人挖掘的区块添加到节点链的端点。
# 首先节点验证该区块，然后将其添加到链上。
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


def init_peers(peers,port):
    """初始化对等节点列表"""
    begin = 8000
    number = 3
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
