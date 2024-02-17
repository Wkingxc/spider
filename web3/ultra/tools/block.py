from hashlib import sha256
import json
import time
import requests

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

# 共识算法
def consensus(blockchain, peers):
    longest_chain = None
    current_len = len(blockchain.chain)

    for node in peers:
        try:
            response = requests.get(f'{node}chain')
            length = response.json()['length']
            chain = response.json()['chain']
            if length > current_len and blockchain.check_chain_validity(chain):
                current_len = length
                longest_chain = chain
        except requests.exceptions.RequestException as e:
            pass

    if longest_chain:
        blockchain = longest_chain
        return True

    return False


def announce_new_block(block, peers):
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

# 在主程序中开始周期性地处理等待队列中的区块
# from threading import Timer
# def manage_pending_blocks_periodically():
#     blockchain.process_pending_blocks()
#     Timer(5, manage_pending_blocks_periodically).start()
