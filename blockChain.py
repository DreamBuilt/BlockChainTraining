# -*- coding=utf-8 -*-
# Author: MrGuan
# CreatData:{}
# Make your life a story worth telling
import hashlib
import time
from datetime import datetime


class Block:
    """
    区块结构
        prev_hash:父块哈希值
        data：   区块内容
        timestamp：区块创建时间
        hash：区块哈希值

    """
    def __init__(self, data, prev_hash):
        # 将传入父块哈希值和数据保存到类变量里
        self.data = data
        self.prev_hash = prev_hash
        # 获取当前的时间
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # 计算区块的哈希值
        # message = hashlib.sha256()
        # message.update(str(self.prev_hash).encode('utf-8'))
        # message.update(str(self.data).encode('utf-8'))
        # message.update(str(self.timestamp).encode('utf-8'))
        self.nonce = None
        self.hash = None
        # self.hash = message.hexdigest()


class BlockChain():
    """
    区块链结构体
    """

    def __init__(self):
        self.blocks = []

    def add_block(self, block):
        "添加区块"
        self.blocks.append(block)

class ProofOfWork():
    """
    工作量证明
    :return:
    """
    def __init__(self,block,diffcult=5):
        self.block = block
        # 定义工作量难度，默认为5，表示有效的哈希值以5个0开头
        self.diffcult = diffcult
    def mine(self):
        """
        挖矿函数
        :return:
        """
        i = 0
        prefix ='0' * self.diffcult
        while True:
            message = hashlib.sha256()
            message.update(str(self.block.prev_hash).encode('utf-8'))
            message.update(str(self.block.data).encode('utf-8'))
            message.update(str(self.block.timestamp).encode('utf-8'))
            message.update(str(i).encode('utf-8'))
            digest = message.hexdigest()
            # print(digest)
            if digest.startswith(prefix):
                self.block.nonce = i
                self.block.hash = digest
                return self.block
            i +=1
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

        prefix = '0'* self.diffcult
        return digest.startswith(prefix)
if __name__ == '__main__':
    # 生成创世区块
    # genesls_block = Block(data="创世区块", prev_hash="")
    # # print(genesls_block)
    # new_block = Block(data='张三转给李四1个比特币', prev_hash=genesls_block.hash)
    # new_block1 = Block(data='张三转给王五2个比特币', prev_hash=new_block.hash)
    #
    # blockChain = BlockChain()
    # blockChain.add_block(genesls_block)
    # blockChain.add_block(new_block)
    # blockChain.add_block(new_block1)
    # print('区块链包含区块的个数：%d\n' % len(blockChain.blocks))
    #
    # for block in blockChain.blocks:
    #     print("父区块哈希值：%s"%block.prev_hash)
    #     print("区块内容：%s"%block.data)
    #     print("区块哈希值：%s"%block.hash)
    #     print("\n")

    # # 定义一个区块
    b = Block(data='测试',prev_hash='')
    # 在定义一个工作量证明
    w = ProofOfWork(b)
    startTime = time.time()
    valid_block = w.mine()
    print(time.time()-startTime)
    startTime1 = time.time()
    print(w.validate())
    print(time.time()-startTime)

    block_chain = BlockChain()
    new_block1 = Block(data='创世区块',prev_hash='')
    w1 = ProofOfWork(new_block1)
    genesis_block = w1.mine()
    block_chain.add_block(genesis_block)

    new_block2 =Block(data='张三转账给李四1个比特币', prev_hash=new_block1.hash)
    w2 = ProofOfWork(new_block2)
    new_block =  w2.mine()
    block_chain.add_block(new_block)

    new_block3 = Block(data='张三转给王五2个比特币', prev_hash=new_block2.hash)
    w3 = ProofOfWork(new_block3)
    new_block = w3.mine()
    block_chain.add_block(new_block)
    print('区块链包含区块的个数：%d\n' % len(block_chain.blocks))

    for block in block_chain.blocks:
        print("父区块哈希值：%s"%block.prev_hash)
        print("区块内容：%s"%block.data)
        print("区块哈希值：%s"%block.hash)
        print("\n")



