# -*- coding=utf-8 -*-
# Author: MrGuan
# CreatData:{}
# Make your life a story worth telling
import base64
import binascii
from _sha256 import sha256

from ecdsa import SigningKey, SECP256k1, VerifyingKey, BadSignatureError
class Wallet():
    """
    签名
    """
    def __init__(self):
        self._private_key = SigningKey.generate(curve=SECP256k1)  # 私钥
        self._public_key = self._private_key.get_verifying_key()  # 公钥


    @property
    def address(self):
        """
        地址
        :return:
        """
        h = self._public_key.to_pem()
        return base64.b64encode(h.digest())

    @property
    def pubkey(self):
        """
        返回公钥字符串
        :return:
        """
        return self._public_key.to_pem()

    def sign(self,message):
        """
        生成数字签名
        :param message:
        :return:
        """
        h = sha256(str(message).encode('utf-8'))
        return binascii.hexlify(self._private_key.sign(h.digest()))


    def verify_sign(self, pubkey,message,signature):
        """
        验证数字签名
        :return:
        """
        verifier = VerifyingKey.from_pem(pubkey)
        h = sha256(str(message).encode('utf-8'))
        return verifier.verify(binascii.unhexlify(signature), h.digest())






