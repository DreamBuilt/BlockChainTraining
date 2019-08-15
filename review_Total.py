# -*- coding=utf-8 -*-
# Author: MrGuan
# CreatData: 2019-08-12 02:44:10
# Make your life a story worth telling
import base64
import binascii
import hashlib
import json
import pickle
import socket
import threading
import time
import traceback
from _sha256 import sha256
from datetime import datetime

from ecdsa import VerifyingKey, SECP256k1, SigningKey

DIFFICULTY = 5


class Wallet():
    def __init__(self):
        self._private_key = SigningKey.generate(curve=SECP256k1)
        self._public_key = self._private_key.get_verifying_key()

    @property
    def address(self):
        """
        生成地址
        :return:
        """
        h = sha256(self._public_key.to_pem())
        return base64.b64encode(h.digest())

    @property
    def pubkey(self):
        """
        返回公钥
        :return:
        """
        return self._public_key.to_pem()

    def sign(self, message):
        """
        生产签名
        :param message:
        :return:
        """
        h = sha256(str(message).encode('utf-8'))
        return binascii.hexlify(self._private_key.sign(h.digest()))


def verify_sign(pubkey, message, signature):
    """
    验证签名
    :param pubkey:公钥
    :param message:内容
    :param signature:签名
    :return:
    """
    verifier = VerifyingKey.from_pem(pubkey)
    h = sha256(str(message).encode('utf-8'))
    return verifier.verify(binascii.unhexlify(signature), h.digest())


class Transaction():
    def __init__(self, sender, recipient, amount):
        """
        初始化发送方，接收方，交易数量
        :param sender:
        :param recipient:
        :param amount:
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
        确保交易的可靠性，需要输入发送者的公钥和签名
        :param pubkey: 公钥
        :param signature: 签名
        :return:
        """
        self.signature = signature
        self.pubkey = pubkey

    def __repr__(self):
        """
        交易分两种，如果发送人为空，则是挖矿奖励，如果不为空，则是普通交易
        :return:
        """
        if self.sender:
            result = "从%s转至%s %d个加密货币" % (self.sender, self.recipient, self.amount)
        else:
            result = "%s挖矿获得%d个加密货币" % (self.recipient, self.amount)
        return result


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
    接受数据及父区块哈希
    """

    def __init__(self, transactions, prev_hash):
        """

        :param transactions:交易对
        :param prev_hash: 父区块哈希值
        """
        self.transactions = transactions
        self.prev_hash = prev_hash
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # 时间戳
        self.nonce = None  # 随机数
        self.hash = None  # 区块哈希值

    # def __repr__(self):
    #     """
    #     打印区块信息
    #     :return:
    #     """
    #     return "区块交易列表:%s 区块哈希值: %s" % (json.dumps(self.transactions), self.hash)


class ProofOfWork():
    """
    工作量证明机制
    """

    def __init__(self, block, miner, difficult=5):
        """
        根据传进来的区块，
        :param block: 区块
        :param difficult: 难度值
        """
        self.block = block
        # 添加挖矿奖励
        self.miner = miner
        # 定义工作量的难度，表示有效hash是由5个0开头的
        self.difficult = DIFFICULTY
        self.reward_amount = 1  # 添加挖矿奖励

    def mine(self):
        """
        挖矿函数
        根据区块的prev_hash,timestamp,data,i,生成的nonce和hash
        :return:
        """

        """
        添加挖矿奖励，每完成一个区块可以获得一个加密货币的奖励
        """

        t = Transaction(
            sender="",
            recipient=self.miner.address,
            amount=self.reward_amount)
        sig = self.miner.sign(json.dumps(t, cls=TransactionEncoder))
        t.set_sign(sig, self.miner.pubkey)
        self.block.transactions.append(t)
        i = 0
        prefix = '0' * self.difficult
        while True:
            message = hashlib.sha256()
            message.update(str(self.block.prev_hash).encode('utf-8'))
            message.update(str(self.block.transactions).encode('utf-8'))
            message.update(str(self.block.timestamp).encode('utf-8'))
            message.update(str(i).encode('utf-8'))
            digest = message.hexdigest()
            if digest.startswith(prefix):
                self.block.nonce = i
                self.block.hash = digest
                return self.block

            i += 1

    def validate(self):
        """
        验证区块有效性
        根据区块的hash,prev_hash,nonce,data生成验证数，验证结果是否符合
        :return:
        """
        message = hashlib.sha256()
        message.update(str(self.block.prev_hash).encode('utf-8'))
        message.update(str(self.block.transactions).encode('utf-8'))
        message.update(str(self.block.timestamp).encode('utf-8'))
        message.update(str(self.block.nonce).encode('utf-8'))
        digest = message.hexdigest()
        prefix = '0' * self.difficult
        return digest.startswith(prefix)


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


block_chain = Block_Chain()


def get_balance(user):
    """
    获取用户的账户余额
    :param user:
    :return:
    """

    balance = 0
    for block in block_chain.blocks:
        for t in block.transactions:
            print(t)
            if t.sender == user.address.decode():
                balance -= t.amount
            elif t.recipient == user.address.decode():
                balance += t.amount
    return balance


NODE_LIST = []

PER_BYTE = 1024

# 去中心网络
class Node(threading.Thread):
    def __init__(self, name, port, host="localhost"):
        threading.Thread.__init__(self, name=name)
        self.name = name
        self.port = port
        self.host = host
        self.wallet = Wallet()
        self.block_chain = None

    def run(self):
        """
        节点运行
        :return:
        """
        self.init_block_chain()
        # 对指定的端口进行监听
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        NODE_LIST.append(
            {
                "name": self.name,
                "host": self.host,
                "port": self.port,
            }
        )
        sock.listen(10)
        print(self.name, "运行中")
        while True:
            connection, address = sock.accept()
            try:
                print(self.name, '处理请求内容.....')
                self.handle_request(connection)
            except socket.timeout:
                print("超时")

            except Exception as e:
                print(e)
                # print(traceback.format_exc())
            connection.close()

    def init_block_chain(self):
        """
        初始化当前节点的区块链
        :return:
        """
        # 若当前网络中已存在其他节点，则从第一个节点获取区块链信息
        if NODE_LIST:
            host = NODE_LIST[0]['host']
            port = NODE_LIST[0]['port']
            name = NODE_LIST[0]['name']
            print(self.name, '发送初始化请求 %s' % (name))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))  # 链接到网络中的第一个节点
            sock.send(pickle.dumps('INIT'))  # 发送初始化请求
            data = []
            while True:
                " 读取区块信息，知道完全获取后退出"
                buf = sock.recv(PER_BYTE)
                if not buf:
                    break
                data.append(buf)
                if len(buf) < PER_BYTE:
                    break
            sock.close()
            self.block_chain = pickle.loads(b''.join(data))
        else:
            # 如果是网络中的第一个节点，初始化一个创世区块
            block = Block(transactions=[], prev_hash='')
            w = ProofOfWork(block, self.wallet)
            genesis_block = w.mine()
            self.block_chain = Block_Chain()
            self.block_chain.add_block(genesis_block)
            print("生成创世区块")

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
        while True:
            buf = connection.recv(PER_BYTE)
            if not buf:
                break
            data.append(buf)
            if len(buf) < PER_BYTE:
                break
        t = pickle.loads(b''.join(data))
        if isinstance(t, Transaction):
            print('处理交易请求....')
            if verify_sign(t.pubkey,
                           str(t),
                           t.signature):
                # 验证签名没有问题，生成一个新的区块
                print(self.name, '交易验证成功')
                new_block = Block(transactions=[t],prev_hash='')
                print(self.name, '生成新的区块....')
                w = ProofOfWork(new_block, self.wallet)
                time.sleep(3)
                block = w.mine()
                print(self.name, "将新区块添加到区块链中")

                self.block_chain.add_block(block)
                print(self.name, "将新区块广播到网络中...")
                self.broadcast_new_block(block)
            else:
                print('交易验证失败')
        elif isinstance(t,Block):
            print('处理新区块的请求')
            if self.verify_block(t):
                print(self.name, '区块验证成功')
                self.block_chain.add_block(t)
                print(self.name, '添加新区块成功')
            else:
                print(self.name,'区块验证失败')
        else:
            connection.send(pickle.dumps(self.block_chain))
    def verify_block(self, block):
        """
        验证区块有效性
        :param block:
        :return:
        """
        message = hashlib.sha256()
        message.update(str(block.prev_hash).encode('utf-8'))
        message.update(str(block.transactions).encode('utf-8'))
        message.update(str(block.timestamp).encode('utf-8'))
        message.update(str(block.nonce).encode('utf-8'))
        digest = message.hexdigest()
        prefix = '0' * DIFFICULTY
        return digest.startswith(prefix)
    def broadcast_new_block(self,block):
        """
        将新生成的区块广播到网络中的其他节点
        :param block:
        :return:
        """
        for node in NODE_LIST:

            host = node['host']
            port = node['port']
            if host == self.host and port == self.port:
                print(self.name, '忽略自身节点')
            else:
                print(self.name, '广播新区块至%s ' %(node['name']))
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建sock对象
                sock.connect((host, port))  # 链接到网络中的节点
                sock.send(pickle.dumps(block))  # 发送新的区块
                sock.close()
    def submit_transaction(self, transaction):
        """
        提交交易到节点中
        :param transaction:
        :return:
        """
        for node in NODE_LIST:
            host = node['host']
            port = node['port']
            if host == self.host and port == self.port:
                print(self.name, '忽略自身节点')
            else:
                print(self.name, '广播新区块至%s:%s'%(self.host, self.port))
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((node['host'], node['port']))
                sock.send(pickle.dumps(transaction))
                sock.close()

    def get_balance(self):
        # 查询钱包的余额
        balance = 0
        for block in self.block_chain.blocks:
            for t in block.transactions:
                if t.sender == self.wallet.address.decode():
                    balance -= t.amount
                elif t.recipient == self.wallet.address.decode():
                    balance += t.amount

    def print_blockchain(self):
        print("区块链包含区块个数: %d\n" % len(self.block_chain.blocks))
        for block in self.block_chain.blocks:
            print("上个区块哈希：%s" % block.prev_hash)
            print("区块内容：%s" % block.transactions)
            print("区块哈希：%s" % block.hash)
            print("\n")

if __name__ == '__main__':
    block_chain = Block_Chain()
    # # 创建3个钱包
    # alice = Wallet()
    # tom = Wallet()
    # bob = Wallet()
    # print("alice：%d个加密货币" % get_balance(alice))
    # print("tom：%d个加密货币" % get_balance(tom))
    # print("bob：%d个加密货币" % get_balance(bob))
    #
    # new_block1 = Block(transactions=[], prev_hash="")
    # # print(type(new_block1))
    # # print(new_block1)
    # w1 = ProofOfWork(new_block1, alice)
    # genesis_block = w1.mine()
    # block_chain.add_block(genesis_block)
    # time.sleep(4)
    # print("alice:%d个加密货币" % (get_balance(alice)))
    # # transaction = []
    # # new_transaction = Transaction(sender=alice.address, recipient=tom.address, amount=0.3)
    # # sig = tom.sign(new_transaction)
    # # new_transaction.set_sign(sig, tom.pubkey)
    # transaction = []
    # new_transaction1 = Transaction(sender=alice.address, recipient=tom.address, amount=0.3)
    # sig = tom.sign(new_transaction1)
    # new_transaction1.set_sign(sig, tom.pubkey)
    # if verify_sign(new_transaction1.pubkey, str(new_transaction1), signature=new_transaction1.signature):
    #
    #     print("验证交易成功")
    #     new_block2 = Block(transactions=[new_transaction1], prev_hash="")
    #     w2 = ProofOfWork(new_block2, bob)
    #     new_block = w2.mine()
    #     block_chain.add_block(new_block)
    #     """
    #     将
    #     """
    # else:
    #     print("验证交易失败")
    #
    # print("alice：%.1f个加密货币" % get_balance(alice))
    # print("tom：%.1f个加密货币" % get_balance(tom))
    # print("bob：%d个加密货币" % get_balance(bob))
    # node1 = Node('节点1',8000)
    # node1.start()
    # time.sleep(5 )
    # node1.print_blockchain()
    #
    # node2 = Node("节点2", 9000)
    # node2.start()
    # time.sleep(5)
    # node2.print_blockchain()
    # new_transaction = Transaction(
    #     sender=node1.wallet.address,
    #     recipient=node2.wallet.address,
    #     amount=0.3)
    # node1.get_balance()
    # node2.get_balance()
    # print("新的内容")
    # sig = node1.wallet.sign(str(new_transaction))
    # new_transaction.set_sign(sig, node1.wallet.pubkey)
    # node1.submit_transaction(new_transaction)
    # time.sleep(5)
    # print(node1.print_blockchain())

    node1 = Node('节点1', 8001)
    node1.start()
    time.sleep(5)
    # node1.print_blockchain()

    node2 = Node("节点2", 9000)
    node2.start()
    time.sleep(5)
    # time.sleep(100000)
    # node2.print_blockchain()

    # node1.get_balance()
    # node2.get_balance()
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