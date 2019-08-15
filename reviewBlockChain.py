# -*- coding=utf-8 -*-
# Author: MrGuan
# CreatData:2019-08-11 20:19:06
# Make your life a story worth telling
import hashlib
from datetime import datetime


class Block():
    """
    根据传入的prev_hash,data生成区块的哈希值
    """

    def __init__(self, prev_hash, data):
        """
        区块链结构体
        :param prev_hash: 父区块哈希值
        :param data: 数据
        :param timestamp:时间戳
        """
        self.prev_hash = prev_hash
        self.data = data
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        message = hashlib.sha256()
        message.update(str(self.prev_hash).encode('utf-8'))
        message.update(str(self.data).encode('utf-8'))
        message.update(str(self.timestamp).encode('utf-8'))
        self.hash = message.hexdigest()


class Block_Chain():
    """
    区块链结构体
    """

    def __init__(self):
        self.blocks = []

    def add_block(self, block):
        """
        将新生成的区块添加进来
        :param block: 区块
        :return:
        """
        self.blocks.append(block)


if __name__ == '__main__':
    genesis_block = Block(prev_hash='', data="创世区块")
    new1block = Block(prev_hash=genesis_block.hash, data="张三给李四转账5个比特币")
    new2block = Block(prev_hash=new1block.hash, data="张三给王五转账2个比特币")

    block_chain = Block_Chain()
    block_chain.add_block(genesis_block)
    block_chain.add_block(new1block)
    block_chain.add_block(new2block)

    print("区块链包含是区块个数: %d" % (len(block_chain.blocks)))
    for block in block_chain.blocks:
        print('父区块哈希值:%s' % (block.prev_hash))
        print('区块数据:%s' %(block.data))
        print('区块哈希值:%s' % (block.hash))
