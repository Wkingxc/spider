from hashlib import sha256
import json
import time

from flask import Flask, request
import requests
import socket
from contextlib import closing

# 基于pow的区块链简单仿真

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index  # 区块索引
        self.transactions = transactions  # 区块包含的交易信息
        self.timestamp = timestamp  # 区块时间戳
        self.hash = None  # 区块哈希值
        self.previous_hash = previous_hash  # 前一个区块的哈希值
        self.nonce = nonce  # 工作量证明的随机数

    def compute_hash(self):
        # 计算区块的哈希值
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()


class Blockchain:
    # 工作量证明算法的难度
    difficulty = 2

    def __init__(self):
        self.unconfirmed_transactions = []  # 待确认的交易列表
        self.chain = []  # 区块链

    def create_genesis_block(self):
        """
        生成创世区块并将其添加到区块链。创世区块的索引为0，前一个哈希为0，具有有效的哈希值。
        """
        genesis_block = Block(0, [], 0, "0")
        genesis_block.hash = genesis_block.compute_hash()
        self.chain.append(genesis_block)

    @property
    def last_block(self):
        return self.chain[-1]  # 获取最后一个区块

    def add_block(self, block, proof):
        """
        验证后将区块添加到区块链。验证包括：
        * 验证工作量证明的有效性。
        * 验证区块中前一个哈希与链中最新区块的哈希匹配。
        """
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if not Blockchain.is_valid_proof(block, proof):
            return False

        block.hash = proof
        self.chain.append(block)
        return True

    @staticmethod
    def proof_of_work(block):
        """
        尝试不同的随机数值以满足难度条件的哈希值。
        """
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    @classmethod
    def is_valid_proof(cls, block, block_hash):
        """
        检查区块哈希是否有效且满足难度条件。
        """
        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())

    @classmethod
    def check_chain_validity(cls, chain):
        result = True
        previous_hash = "0"

        for block in chain:
            block_hash = block.hash
            # 删除哈希字段以重新计算哈希
            delattr(block, "hash")

            if not cls.is_valid_proof(block, block_hash) or \
                    previous_hash != block.previous_hash:
                result = False
                break

            block.hash, previous_hash = block_hash, block_hash

        return result

    def mine(self):
        """
        这个函数用作接口，将待确认的交易添加到区块链中，并执行工作量证明。
        """
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)

        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)

        self.unconfirmed_transactions = []

        return True


app = Flask(__name__)

# 节点的区块链副本
blockchain = Blockchain()
blockchain.create_genesis_block()

# 对等节点列表
peers = set()


# 提交新交易的端点。应用程序将使用此端点将新数据（帖子）添加到区块链中
@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    tx_data = request.get_json()
    required_fields = ["author", "content"]

    for field in required_fields:
        if not tx_data.get(field):
            return "无效的交易数据", 404

    tx_data["timestamp"] = time.time()

    blockchain.add_new_transaction(tx_data)

    return "成功", 201


# 返回节点区块链副本的端点。
# 我们的应用程序将使用此端点查询所有帖子以显示。
@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json.dumps({"length": len(chain_data),
                       "chain": chain_data,
                       "peers": list(peers)})


# 请求节点挖掘待确认交易的端点（如果有）。我们将使用它来从应用程序本身启动挖掘命令。
@app.route('/mine', methods=['GET'])
def mine_unconfirmed_transactions():
    result = blockchain.mine()
    if not result:
        return "没有交易可挖掘"
    else:
        # 确保在向网络宣布之前具有最长的链
        consensus() # 通过共识，如果有更长的链，就替换掉当前的链
        # 向网络宣布最近挖掘的区块
        announce_new_block(blockchain.last_block)
        return "区块 #{} 已挖掘。".format(blockchain.last_block.index)


# 添加新节点到网络的端点
@app.route('/register_node', methods=['POST'])
def register_new_peers():
    node_address = request.get_json()["node_address"]
    if not node_address:
        return "无效的数据", 400

    # 将节点添加到对等节点列表
    peers.add(node_address)

    # 返回最新的共识区块链以同步
    return get_chain()


@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    """
    内部调用`register_node`端点来注册当前节点到请求中指定的节点，并同步区块链以及对等节点数据。
    """
    des_address = request.get_json()["des_address"]
    if not des_address:
        return "无效的数据", 400

    data = {"node_address": request.host_url} # 本节点的地址
    headers = {'Content-Type': "application/json"}

    # 向远程节点发送注册请求并获取信息
    response = requests.post(des_address + "register_node",
                             data=json.dumps(data), headers=headers)

    if response.status_code == 200:
        global blockchain
        global peers
        # 更新链和对等节点
        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)
        new_peers = set(response.json()['peers'])
        new_peers.discard(request.host_url)  # 移除自己的地址
        new_peers.add(des_address)  # 添加远程节点的地址
        peers.update(new_peers) # 更新本节点的peers(对等节点)
        return "注册成功", 200
    else:
        # 如果出现问题，将其传递给API响应
        return response.content, response.status_code


def create_chain_from_dump(chain_dump):
    generated_blockchain = Blockchain()
    generated_blockchain.create_genesis_block()
    for idx, block_data in enumerate(chain_dump):
        if idx == 0:
            continue  # 跳过创世区块
        block = Block(block_data["index"],
                      block_data["transactions"],
                      block_data["timestamp"],
                      block_data["previous_hash"],
                      block_data["nonce"])
        proof = block_data['hash']
        added = generated_blockchain.add_block(block, proof)
        if not added:
            raise Exception("链数据已篡改！")
    return generated_blockchain


# 用于将其他人挖掘的区块添加到节点链的端点。
# 首先节点验证该区块，然后将其添加到链上。
@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    block_data = request.get_json()
    block = Block(block_data["index"],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],
                  block_data["nonce"])

    proof = block_data['hash']
    added = blockchain.add_block(block, proof)

    if not added:
        return "节点丢弃了该区块", 400

    return "区块已添加到链上", 201


# 查询待确认交易的端点
@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions)


def consensus():
    """
    我们简单的共识算法。如果找到更长的有效链，我们将替换为该链。
    """
    global blockchain

    longest_chain = None    
    current_len = len(blockchain.chain)

    for node in peers:
        response = requests.get('{}chain'.format(node))
        length = response.json()['length']
        chain = response.json()['chain']
        if length > current_len and blockchain.check_chain_validity(chain):
            current_len = length
            longest_chain = chain

    if longest_chain:
        blockchain = longest_chain
        return True

    return False


def announce_new_block(block):
    """
    在挖掘出区块后向网络宣布区块。其他节点可以验证工作量证明并将其添加到各自的链上。
    """
    for peer in peers:
        url = "{}add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        requests.post(url,
                      data=json.dumps(block.__dict__, sort_keys=True),
                      headers=headers)



def check_port(port):
    """检查端口是否被占用"""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        if sock.connect_ex(('localhost', port)) == 0:
            return True  # 端口被占用
        else:
            return False  # 端口未被占用

if __name__ == "__main__":
    port = 8000
    while check_port(port):
        port += 1

    print("使用端口：", port)
    app.run(debug=True, threaded=True, port=port,use_reloader=False)