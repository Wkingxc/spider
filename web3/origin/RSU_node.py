from hashlib import sha256
import json
import time
import argparse

from flask import Flask, request
import requests

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
        self.unconfirmed_transactions = None  # 待确认的认证
        self.chain = []  # 区块链
        self.pending_blocks = []  # 新增：等待处理的区块

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
            self.pending_blocks.append(block)  # 修改：将无法处理的区块放入等待队列
            return False
        
        block.hash = block.compute_hash()
        self.chain.append(block)
        return True

    # 新增：处理等待队列中的区块
    def process_pending_blocks(self):
        i = 0
        while i < len(self.pending_blocks):
            pending_block = self.pending_blocks[i]
            previous_hash = self.last_block.hash
            if previous_hash == pending_block.previous_hash:
                pending_block.hash = pending_block.compute_hash()
                self.chain.append(pending_block)
                self.pending_blocks.pop(i)
                i = 0  # 重置索引，从头开始遍历
            else:
                i += 1  # 如果不能添加到链上，就处理下一个区块

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

        tx = self.unconfirmed_transactions
        last_block = self.last_block
        new_block = Block(index=last_block.index + 1,
                            transactions=tx,
                            timestamp=time.time(),
                            previous_hash=last_block.hash)
        self.add_block(new_block)

        return new_block


app = Flask(__name__)

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
    tx_data = request.get_json()
    required_fields = ["author", "content"]

    for field in required_fields:
        if not tx_data.get(field):
            return "无效的交易数据", 404

    tx_data["timestamp"] = time.time()
    blockchain.unconfirmed_transactions = tx_data

    # 将该交易添加到区块链中
    new_block = blockchain.mine()    
    if not new_block:
        return "上链失败"
    else:
        consensus() # 通过共识，如果有更长的链，就替换掉当前的链
        announce_new_block(new_block)
        return f"区块{str(tx_data)}已添加到链上", 200


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
    在挖掘出区块后向网络宣布区块。其他节点可以将其添加到各自的链上。
    """
    for peer in peers:
        url = f"{peer}add_block"
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

# 在主程序中开始周期性地处理等待队列中的区块
# from threading import Timer
# def manage_pending_blocks_periodically():
#     blockchain.process_pending_blocks()
#     Timer(5, manage_pending_blocks_periodically).start()

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
