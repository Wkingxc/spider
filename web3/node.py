from hashlib import sha256
import json
import time
import argparse

from flask import Flask, request
import requests
import socket
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor


# 基于PBFT的区块链简单仿真

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index  # 区块索引
        self.transactions = transactions  # 区块包含的交易信息
        self.timestamp = timestamp  # 区块时间戳
        self.hash = None  # 区块哈希值
        self.previous_hash = previous_hash  # 前一个区块的哈希值

    def compute_hash(self):
        # 计算区块的哈希值
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()


class Blockchain:

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

    def add_block(self, block):
        """
        将区块添加到区块链。验证包括：
        * 验证区块中前一个哈希与链中最新区块的哈希匹配。
        """
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False
        
        block.hash = block.compute_hash()
        self.chain.append(block)
        return True

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    @classmethod
    def check_chain_validity(cls, chain):
        result = True
        previous_hash = "0"

        for block in chain:
            # 检查区块的previous_hash是否等于前一个区块的哈希值
            if previous_hash != block.previous_hash:
                result = False
                break

            previous_hash = block.hash

        return result

    def mine(self):
        """
        将本节点中待确认的交易添加到区块链中。
        """
        if not self.unconfirmed_transactions:
            return False

        new_blocks = []
        while self.unconfirmed_transactions:
            tx = self.unconfirmed_transactions.pop(0)
            last_block = self.last_block
            new_block = Block(index=last_block.index + 1,
                              transactions=tx,
                              timestamp=time.time(),
                              previous_hash=last_block.hash)
            self.add_block(new_block)
            new_blocks.append(new_block)

        return new_blocks


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

    return "成功，交易数据： " + str(tx_data), 201


# 返回节点区块链副本的端点。
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
        consensus() # 通过共识，如果有更长的链，就替换掉当前的链
        for block in result:
            announce_new_block(block)
        return f"已挖掘 {len(result)} 个区块。"


# 用于将其他人挖掘的区块添加到节点链的端点。
# 首先节点验证该区块，然后将其添加到链上。
@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    block_data = request.get_json()
    block = Block(block_data["index"],
                  block_data["transactions"],
                  block_data["timestamp"],
                  block_data["previous_hash"],)

    blockchain.add_block(block)

    return f"区块{block.index}已添加到链上", 201


# 查询待确认交易的端点
@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions)



def consensus():
    global blockchain

    longest_chain = None
    current_len = len(blockchain.chain)

    for node in peers:
        
        response = requests.get(f'{node}chain')
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
        try:
            requests.post(url,
                        data=json.dumps(block.__dict__, sort_keys=True),
                        headers=headers,
                        timeout=0.001)
        except requests.exceptions.Timeout:
            pass



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
    app.run(debug=True, threaded=True, port=port)