# -*- coding=utf-8 -*-
# Author: MrGuan
# CreatData: 2019-08-12 02:23:38
# Make your life a story worth telling
import json
from datetime import datetime


class Block():
    """
    接受数据及父区块哈希
    """

    def __init__(self, transactions, prev_hash):
        """

        :param transactions:交易列表
        :param prev_hash: 父区块哈希值
        """
        self.transactions = transactions
        self.prev_hash = prev_hash
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # 时间戳
        self.hash = None  # 区块哈希值
        self.nonce = None  # 随机数

    def __repr__(self):
        """
        打印区块信息
        :return:
        """
        return "交易列表为:%s 区块哈希值: %s" % (self.transactions, self.hash)

class Transaction():
    def __init__(self, sender, recipient, amount):
        """
        初始化发送方，接收方，交易数量
        :param sender:
        :param recipient:
        :param amount:
        """
        if isinstance(sender, bytes):
            self.sender = sender.decode('utf-8')
        self.sender = sender
        if isinstance(recipient, bytes):
            self.recipient = recipient.decode('utf-8')
        self.recipient = recipient
        self.amount = amount

    def set_sign(self, pubkey, signature):
        """
        确保交易的可靠性，需要输入发送者的公钥和签名
        :param pubkey: 公钥
        :param signature: 签名
        :return:
        """
        self.pubkey = pubkey
        self.signature = signature

    def __repr__(self):
        """
        交易分两种，如果发送人为空，则是挖矿奖励，如果不为空，则是普通交易
        :return:
        """
        if self.sender:
            result = "从%s转至%s %d个加密货币" % (self.sender, self.recipient, self.amount)
        else:
            result = "%s挖矿获得%d个加密货币奖励" %(self.recipient, self.amount)
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