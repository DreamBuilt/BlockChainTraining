# -*- coding=utf-8 -*-
# Author: MrGuan
# CreatData:{}
# Make your life a story worth telling
import hashlib
from datetime import datetime


class Block():
    """
    区块结构
    prev_hash  父块哈希值
    hash 块哈希值
    nonce 随机数
    data 数据
    timestamp 时间戳
    """

    def __init__(self, data, prev_hash):
        self.data = data
        self.prev_hash = prev_hash
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.nonce = None
        self.hash = None


class Block_Chain():
    """
    区块链结构
    blocks 包含区块的列表
    """

    def __init__(self):
        self.blocks = []

    def addBlock(self, block):
        # 添加区块
        self.blocks.append(block)


class ProofOfWork():
    """
    工作量证明
    """

    def __init__(self, block, difficulty=5):
        self.block = block
        self.difficulty = difficulty

    def mine(self):
        """
        挖矿
        :return:
        """
        i = 0
        prefix = '0' * self.difficulty
        while True:
            message = hashlib.sha256()
            message.update(str(self.block.prev_hash).encode('utf-8'))
            message.update(str(self.block.data).encode('utf-8'))
            message.update(str(self.block.timestamp).encode('utf-8'))
            message.update(str(i).encode('utf-8'))
            digest = message.hexdigest()
            print(digest)
            if digest.startswith(prefix):
                self.block.hash = digest
                self.block.nonce = i
                return self.block
            i += 1

    def validate(self):
        """
        验证有效性
        :return:
        """
        message = hashlib.sha256()
        message.update(str(self.block.prev_hash).encode('utf-8'))
        message.update(str(self.block.data).encode('utf-8'))
        message.update(str(self.block.timestamp).encode('utf-8'))
        message.update(str(self.block.nonce).encode('utf-8'))
        digest = message.hexdigest()
        prefix = '0' * self.difficulty
        return digest.startswith(prefix)


if __name__ == '__main__':
    b = Block('测试', '')
    w = ProofOfWork(b)
    valid_block = w.mine()
    print(w.validate())
    block_chain = Block_Chain()

    new_block1 = Block(data="创世区块", prev_hash='')
    w1 = ProofOfWork(new_block1)
    genesis_block = w1.mine()
    block_chain.addBlock(genesis_block)

    new_block2 = Block(data='张三转账给李四1个比特币',prev_hash=new_block1.hash)
    w2 = ProofOfWork(new_block2)
    new_block = w2.mine()
    block_chain.addBlock(new_block)

    new_block3 = Block(data='张三转账给王五2个比特币',prev_hash=new_block2.hash)
    w3 = ProofOfWork(new_block3)
    new_block = w3.mine()
    block_chain.addBlock(new_block3)


