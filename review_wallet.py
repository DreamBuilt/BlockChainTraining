# -*- coding=utf-8 -*-
# Author: MrGuan
# CreatData: 2019-08-12 00:36:45
# Make your life a story worth telling

# 倒入椭圆曲线函数包
import base64
import binascii
from _sha256 import sha256

from ecdsa import SigningKey, SECP256k1, VerifyingKey


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


if __name__ == '__main__':
    w = Wallet()
    # 打印钱包地址
    print(w.address)
    # 打印钱包公钥
    print(w.pubkey)
    # 测试数据
    data = "测试"
    # 生成签名
    sig = w.sign(data)
    # 打印签名
    print(sig)
    # 校验签名
    print(verify_sign(w.pubkey,data, sig))