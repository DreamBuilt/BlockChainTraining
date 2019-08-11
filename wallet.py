# -*- coding=utf-8 -*-
# Author: MrGuan
# CreatData:{}
# Make your life a story worth telling


# 钱包，账户，交易功能
# 椭圆曲线算法
import time
import base64
import hashlib
import pickle
import socket
import threading
import traceback
# socket.setdefaulttimeout(20)
from _sha256 import sha256

import binascii
from datetime import datetime

from ecdsa import SigningKey, SECP256k1, VerifyingKey, BadSignatureError
import json

DIFFICULTY = 5
# 定义一个全局列表保存所有节点
NODE_LIST = []


class Wallet():
    """
    钱包
    """

    def __init__(self):
        """
        钱包初始化时基于椭圆曲线生成一个唯一的秘钥对，代表区块链上唯一一个账户
        """
        self._private_key = SigningKey.generate(curve=SECP256k1)
        self._public_key = self._private_key.get_verifying_key()

        """
        生成签名，创建账户之后，还需要提供这个账户的公钥和地址并利用私钥生成签名。
        地址是由公钥经过Base64算法计算而成的，签名生成的是一串二进制字符串便于查看
        这里是将二进制字符串转换为ASCII字符进行输出
        """

    @property
    def address(self):
        """
        通过这里生成公钥地址
        :return:

        """
        h = sha256(self._public_key.to_pem())
        return base64.b64encode(h.digest())

    @property
    def pubkey(self):
        """
        返回公钥字符串

        :return:
        """
        return self._public_key.to_pem()

    def sign(self, message):
        """
        生成数字签名
        :param message:
        :return:
        """
        h = sha256(str(message).encode('utf-8'))
        return binascii.hexlify(self._private_key.sign(h.digest()))


def verify_sign(pubkey, message, signature):
    """
    验证签名
    :return:
    """
    verifier = VerifyingKey.from_pem(pubkey)
    h = sha256(str(message).encode('utf-8'))
    return verifier.verify(binascii.unhexlify(signature), h.digest())


class Transaction():
    def __init__(self, sender, recipient, amount):
        """
        初始化交易，设置交易的发送方，接受方，交易数量
        :param sender: 发送方
        :param recipient: 接受方
        :param amount: 交易数量
        """
        if isinstance(sender, bytes):
            sender = sender.decode('utf-8')
        self.sender = sender
        if isinstance(recipient, bytes):
            recipient = recipient.decode('utf-8')
        self.recipient = recipient
        self.amount = amount

    def set_sign(self, signature, pubkey):
        """
        为了便于验证这个交易的可靠性，需要发送方输入他的公钥和签名
        :param signature:
        :param pubkey:
        :return:
        """
        self.signature = signature  # 签名
        self.pubkey = pubkey  # 公钥

    def __repr__(self):
        """
        交易大可分为2种，一种是挖矿所得，一种的转账交易
        挖矿所得没有发送方，以此进行区分显示不同的内容
        :return:
        """
        if self.sender:
            s = "从 %s 转至 %s %d个加密货币" % (self.sender, self.recipient, self.amount)
        else:
            s = "%s 挖矿获得%d个加密货币" % (self.recipient, self.amount)
        return s


class TransactionEncoder(json.JSONEncoder):
    """
    定义Json的编码类，用来序列化Transaction
    """

    def default(self, obj):
        if isinstance(obj, Transaction):
            return obj.__dict__
        else:
            return json.JSONEncoder.default(self, obj)


class Block():
    """
    区块结构

    transactions:交易列表
    """

    def __init__(self, transactions, prev_hash):
        """
        更新为交易列表
        :param transactions:
        :param prev_hash:
        """
        self.transactions = transactions
        self.prev_hash = prev_hash

        self.prev_hash = prev_hash
        # 获取当前的时间
        self.timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.nonce = None
        self.hash = None


class ProofOfWork():
    """
    工作量证明
    :return:
    """

    def __init__(self, block, miner, diffcult=5):
        self.block = block

        # 定义工作量难度，默认为5，表示有效的哈希值以5个0开头
        self.difficulty = DIFFICULTY

        self.miner = miner
        #  添加挖矿奖励
        self.reward_amount = 1

    def mine(self):
        """
        挖矿函数
        :return:
        """
        i = 0
        prefix = '0' * self.difficulty
        """
            添加奖励
        """
        t = Transaction(
            sender="",
            recipient=self.miner.address,
            amount=self.reward_amount,
        )
        sig = self.miner.sign(json.dumps(t, cls=TransactionEncoder))
        t.set_sign(sig, self.miner.pubkey)
        self.block.transactions.append(t)

        while True:
            message = hashlib.sha256()
            message.update(str(self.block.prev_hash).encode('utf-8'))
            message.update(str(self.block.transactions).encode('utf-8'))
            message.update(str(self.block.timestamp).encode('utf-8'))
            message.update(str(i).encode('utf-8'))
            digest = message.hexdigest()
            # print(digest)
            if digest.startswith(prefix):
                self.block.nonce = i
                self.block.hash = digest

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


class BlockChain():
    """
    区块链结构体
    """

    def __init__(self):
        self.blocks = []

    def add_block(self, block):
        "添加区块"
        self.blocks.append(block)


blockchain = BlockChain()
PER_BYTE = 1024


def get_balance(user):
    """
    查询所有的交易记录
    :param user:
    :return:
    """

    balance = 0
    for block in blockchain.blocks:
        for t in block.transactions:
            if t.sender == user.address.decode():
                balance -= t.amount
            elif t.recipient == user.address.decode():
                balance += t.amount
    return balance


class Node(threading.Thread):
    def __init__(self, name, port, host='localhost'):
        threading.Thread.__init__(self, name=name)
        self.host = host
        self.port = port
        self.name = name
        self.wallet = Wallet()
        self.blockchain = None

    def run(self):
        """
        节点运行
        :return:
        """
        self.init_blockchain()  # 初始化区块链

        # 指定端口进行监听
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        NODE_LIST.append({
            'name': self.name,
            'host': self.host,
            'port': self.port
        })
        sock.listen(10)
        print(self.name, '运行中...')
        while True:
            connection, address = sock.accept()
            try:
                print(self.name, '处理请求内容...')
                self.handle_request(connection)
            except socket.timeout:
                print('超时!')
            except Exception as e:
                # print(e)
                print(str(traceback.format_exc()))
            connection.close()

    def handle_request(self, connection):
        """
        处理请求
        1.初始化请求，收到该请求后节点将返回本地的区块链信息
        2.新的交易广播，收到该请求，收到这类请求节点验证该交易是否有效，如果有效则进行挖矿，生成一个新的区块添加到本地区块链并广播到整个网络中
        3.新区块广播，，收到该类请求，先验证该区块是否有效，如果有效，则添加到本地区块链后面
        :param connection:
        :return:
        """
        data = []
        while True:  # 不断读取请求数据直至读取完成
            buf = connection.recv(PER_BYTE)
            if not buf:  # 若读取不到新的数据则退出
                break
            data.append(buf)
            if len(buf) < PER_BYTE:  # 若读取到的数据长度小于规定长度，说明数据读取完成，退出
                break
        t = pickle.loads(b''.join(data))
        if isinstance(t, Transaction):  # 如果是新区块类型类型消息
            print("处理交易请求...")
            if verify_sign(t.pubkey,
                           str(t),
                           t.signature):

                # 验证交易签名没问题，生成一个新的区块
                print(self.name, "验证交易成功")
                new_block = Block(transactions=[t], prev_hash="")
                print(self.name, "生成新的区块...")
                w = ProofOfWork(new_block, self.wallet)
                block = w.mine()
                print(self.name, "将新区块添加到区块链中")
                self.blockchain.add_block(block)
                print(self.name, "将新区块广播到网络中...")
                self.broadcast_new_block(block)
            else:
                print(self.name, "交易验证失败！")
        elif isinstance(t, Block):
            print("处理新区块请求...")
            if self.verify_block(t):
                print(self.name, "区块验证成功")
                self.blockchain.add_block(t)
                print(self.name, "添加新区块成功")
            else:
                print(self.name, "区块验证失败!")
        else:  # 如果不是新区块消息，默认为初始化消息类型，返回本地区块链内容
            connection.send(pickle.dumps(self.blockchain))

    def verify_block(self, block):
        """
        验证区块的有效性
        :param block:
        :return:
        """
        message = hashlib.sha256()
        message.update(str(block.prev_hash).encode('utf-8'))
        #  更新区块中的交易数据
        message.update(str(block.transactions).encode('utf-8'))
        message.update(str(block.timestamp).encode('utf-8'))
        message.update(str(block.nonce).encode('utf-8'))
        digest = message.hexdigest()
        prefix = '0' * DIFFICULTY

        return digest.startswith(prefix)

    def broadcast_new_block(self, block):
        """
        广播数据
        :return:
        """
        for node in NODE_LIST:
            host = node['host']
            port = node['port']

            if host == self.host and port == self.port:
                print(self.name, '忽略自身节点')
            else:
                print(self.name, ' 广播新区块至 %s ' % (node['name']))
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))  # 连接到网络的节点中
                sock.send(pickle.dumps(block))  # 发送新区块
                sock.close()  # 发送完成后关闭连接

    def init_blockchain(self):
        """
        初始化当前节点的区块链
        :return:
        """
        if NODE_LIST:  # 如果网络存在已存在其他节点，则从第一个节点从获取区块链信息
            host = NODE_LIST[0]["host"]
            port = NODE_LIST[0]['port']
            name = NODE_LIST[0]['name']
            # print(host, port)
            print(self.name, '发送初始化请求 %s' % (name))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))  # 链接到网络中的第一个节点
            sock.send(pickle.dumps('INIT'))  # 发送初始化请求
            data = []
            while True:  # 读取区块信息，直至获取后退出
                buf = sock.recv(PER_BYTE)
                if not buf:
                    break
                data.append(buf)
                if len(buf) < PER_BYTE:
                    break
            sock.close()

            # 将获取的区块链信息赋值到当前节点
            self.blockchain = pickle.loads(b''.join(data))
            print(self.name, '初始化完成')

        else:
            # 如果是网络中的第一个节点， 初始化一个创世区块
            block = Block(transactions=[], prev_hash='')
            w = ProofOfWork(block, self.wallet)
            genesis_block = w.mine()
            self.blockchain = BlockChain()
            self.blockchain.add_block(genesis_block)
            print('生成创世区块')

    def submit_transaction(self, transaction):
        """
        交易并广播到去中心化网络中

        :return:
        :transaction 交易
        """
        for node in NODE_LIST:
            host = node['host']
            port = node['port']
            if host == self.host and port == self.port:
                print(self.name, '忽略自身节点')
            else:
                print(self.name, '广播新区块至%s:%s' % (self.host, self.port))
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((node["host"], node["port"]))
                sock.send(pickle.dumps(transaction))
                sock.close()

    def get_balance(self):
        balance = 0
        for block in self.blockchain.blocks:
            for t in block.transactions:
                if t.sender == self.wallet.address.decode():
                    balance -= t.amount
                elif t.recipient == self.wallet.address.decode():
                    balance += t.amount
        print('当前拥有%.1f个加密货币' % (balance))

    def print_blockchain(self):
        """
        打印区块链信息
        :return:
        """
        print("区块链包含区块个数:%d\n" % len(self.blockchain.blocks))
        for block in self.blockchain.blocks:
            print('父区块哈希: %s' % block.prev_hash)
            print('区块内容：%s' % block.transactions)
            print('区块哈希:%s' % block.hash)
            print('\n')


if __name__ == '__main__':
    # alice = Wallet()
    # tom = Wallet()
    # bob = Wallet()

    # print("alice:%d个加密货币" % (get_balance(alice)))
    # print("tom:%d个加密货币" % (get_balance(tom)))
    # print("tom:%d个加密货币" % (get_balance(bob)))
    #
    # new_block1 = Block(transactions=[], prev_hash='')
    # w1 = ProofOfWork(new_block1, alice)
    # genesis_block = w1.mine()
    # blockchain.add_block(genesis_block)
    # print("alice:%d个加密货币" % (get_balance(alice)))
    #
    # transactions = []
    # new_transaction = Transaction(
    #     sender=alice.address,
    #     recipient=tom.address,
    #     amount=0.3
    # )
    # sig = tom.sign(new_transaction)
    # new_transaction.set_sign(sig, tom.pubkey)
    # print("alice:%d个加密货币" % (get_balance(alice)))
    # print("tom:%d个加密货币" % (get_balance(tom)))
    # print("bob:%d个加密货币" % (get_balance(bob)))
    # if verify_sign(new_transaction.pubkey, str(new_transaction), new_transaction.signature):
    #     print('验证交易成功')
    #     new_block2 = Block(transactions=[new_transaction], prev_hash='')
    #     print("生成新的区块")
    #     w2 = ProofOfWork(new_block2, bob)
    #     block = w2.mine()
    #     print("将新的区块添加到区块链中")
    #     blockchain.add_block(block)
    # else:
    #     print('交易验证失败')
    # print("alice:%.1f个加密货币" % (get_balance(alice)))
    # print("tom:%.1f个加密货币" % (get_balance(tom)))
    # print("bob:%d个加密货币" % (get_balance(bob)))

    node1 = Node('节点1', 8001)
    node1.start()
    time.sleep(5)
    node1.print_blockchain()

    node2 = Node("节点2", 9000)
    node2.start()
    time.sleep(5)
    # time.sleep(100000)
    node2.print_blockchain()

    node1.get_balance()
    node2.get_balance()
    print("\n")
    new_transaction = Transaction(
        sender=node1.wallet.address,
        recipient=node2.wallet.address,
        amount=0.3
    )
    sig = node1.wallet.sign(new_transaction)
    new_transaction.set_sign(sig, node1.wallet.pubkey)
    node1.submit_transaction(new_transaction)
    time.sleep(3)
    node1.print_blockchain()

    time.sleep(3)
    node2.print_blockchain()
    time.sleep(3)
    node1.get_balance()
    time.sleep(3)
    node2.get_balance()
    # new_transaction = Transaction(
    #     sender=node1.wallet.address,
    #     recipient=node2.wallet.address,
    #     amount=0.3
    # )
    # sig = node1.wallet.sign(str(new_transaction))
    # new_transaction.set_sign(sig, node1.wallet.pubkey)
    # w = Wallet()
    # # 打印钱包地址
    # print(w.ad
    # .
    #
    # .0dress)
    # # 打印钱包公钥
    # print(w.pubkey)
    #
    # # 测试数据
    # data = '交易数据'
    # sig = w.sign(data)
    # # 打印签名
    # print(sig)
    #
    # # 验证签名
    # print(w.verify_sign(w.pubkey, data, sig))
