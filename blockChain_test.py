# -*- coding=utf-8 -*-
# Author: MrGuan
# CreatData:{}
# Make your life a story worth telling
import hashlib
from datetime import datetime


class Block():
    """
    区块结构体：
    父块哈希值：prev_hash
    哈希值：hash
    时间戳：timestamp
    区块数据：data
    """

    def __init__(self, data, prev_hash):
        self.data = data
        self.prev_hash = prev_hash
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # message = hashlib.sha256()
        # message.update(str(self.prev_hash).encode('utf-8'))
        # message.update(str(self.data).encode('utf-8'))
        # message.update(str(self.timestamp).encode('utf-8'))
        self.hash = None
        # self.hash = message.hexdigest()
        self.nonce = None


class ProofWork():
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
            if digest.startswith(prefix):
                self.block.nonce = i
                self.block.hash = digest
                return self.block
            i += 1

    def validate(self):
        '''
        验证有效性
        :return:
        '''
        message = hashlib.sha256()
        message.update(str(self.block.prev_hash).encode('utf-8'))
        message.update(str(self.block.data).encode('utf-8'))
        message.update(str(self.block.timestamp).encode('utf-8'))
        message.update(str(self.block.nonce).encode('utf-8'))
        digest = message.hexdigest()
        prefix = '0' * self.difficulty
        return digest.startswith(prefix)


class Block_Chain():
    """
    区块链结构体
    block ：包含区块的列表
    """

    def __init__(self):
        self.blocks = []

    def add_Block(self, block):
        self.blocks.append(block)


if __name__ == '__main__':
    # genesis_block = Block(data="创世区块", prev_hash='')
    # new_block0 = Block(data="张三转给李四一个比特币", prev_hash=genesis_block.hash)
    # new_block1 = Block(data="张三转给王五两个比特币", prev_hash=new_block0.hash)
    #
    # block_chain = Block_Chain()
    # block_chain.add_Block(genesis_block)
    # block_chain.add_Block(new_block0)
    # block_chain.add_Block(new_block1)
    #
    # print('区块链所含的区块个数:%d' % len(block_chain.blocks))
    # for block in block_chain.blocks:
    #     print('父区块哈希值:%s' % block.prev_hash)
    #     print('区块数据：%s' % block.data)
    #     print('区块哈希值%s' % block.hash)
    b = Block(data='测试', prev_hash="")
    w = ProofWork(b)
    valid_block = w.mine()
    # print(valid_block)
    print(w.validate())
