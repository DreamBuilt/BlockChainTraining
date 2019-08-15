# -*- coding=utf-8 -*-
# Author: MrGuan
# CreatData: 2019-08-11 21:03:41
# Make your life a story worth telling
import hashlib
import time
from datetime import datetime


class Block():
    """
    接受数据及父区块哈希
    """

    def __init__(self, data, prev_hash):
        """

        :param data:区块内容
        :param prev_hash: 父区块哈希值
        """
        self.data = data
        self.prev_hash = prev_hash
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # 时间戳
        self.hash = None  # 区块哈希值
        self.nonce = None  # 随机数

    def __repr__(self):
        """
        打印区块信息
        :return:
        """
        return "区块内容:%s 区块哈希值: %s" % (self.data, self.hash)


class ProofOfWork():
    """
    工作量证明机制
    """

    def __init__(self, Block, difficult=5):
        """
        根据传进来的区块，
        :param Block: 区块
        :param difficult: 难度值
        """
        self.Block = Block
        # 定义工作量的难度，表示有效hash是由5个0开头的
        self.difficult = difficult

    def mine(self):
        """
        挖矿函数
        根据区块的prev_hash,timestamp,data,i,生成的nonce和hash
        :return:
        """
        i = 0
        prefix =  '0' *self.difficult
        while True:
            message = hashlib.sha256()
            message.update(str(self.Block.prev_hash).encode('utf-8'))
            message.update(str(self.Block.timestamp).encode('utf-8'))
            message.update(str(self.Block.data).encode('utf-8'))
            message.update(str(i).encode('utf-8'))
            digest = message.hexdigest()
            if digest.startswith(prefix):
                self.Block.hash = digest
                self.Block.nonce = i
                return self.Block
            i +=1
    def validate(self):
        """
        验证区块有效性
        根据区块的hash,prev_hash,nonce,data生成验证数，验证结果是否符合
        :return:
        """
        message = hashlib.sha256()
        message.update(str(self.Block.prev_hash).encode('utf-8'))
        message.update(str(self.Block.timestamp).encode('utf-8'))
        message.update(str(self.Block.data).encode('utf-8'))
        message.update(str(self.Block.nonce).encode('utf-8'))
        digest = message.hexdigest()
        prefix = '0' * self.difficult
        return digest.startswith(prefix)
class BlockChain():
    """
    区块链结构
    """
    def  __init__(self):
        self.blocks= []
    def add_block(self, block):
        self.blocks.append(block)
if __name__ == '__main__':
    # 定义一个区块
    b = Block(data='测试', prev_hash='')
    #在定义一个工作证明
    w = ProofOfWork(b)
    startTime = time.time()
    w.mine()
    print("挖矿所用时间",time.time()-startTime)
    startTime = time.time()
    print(w.validate())
    print("测试所花时间：",time.time()-startTime)

    # 测试工作量证明
    # 初始化一个区块链的对象，创建一个新块对象，将新建的块对象传递给工作量证明，得到有工作量证明的对象，
    # 将新增的工作对象添加到区块链对象中
    blockchain = BlockChain()
    new_block1 = Block(data="创世区块",prev_hash="")
    w1 = ProofOfWork(new_block1)
    genesis_block = w1.mine()
    blockchain.add_block(genesis_block)

    new_block2 = Block(data="张三给李四转账5个加密货币",prev_hash=new_block1.hash)
    w2 = ProofOfWork(new_block2)
    new_block = w2.mine()
    blockchain.add_block(new_block)

    new_block3 = Block(data='张三转账给王五2个加密货币', prev_hash=new_block2.hash)
    w3 = ProofOfWork(new_block3)
    new_block = w3.mine()
    blockchain.add_block(new_block)
    # 打印出区块链里面的父块哈希值，区块哈希值，块内容
    for block in blockchain.blocks:
        print("父块哈希值：%s" %(block.prev_hash))
        print("块哈希值：%s" %(block.hash))
        print("区块内容：%s" %(block.data))
        print("\n")


