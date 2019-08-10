# -*- coding=utf-8 -*-
# Author: MrGuan
# CreatData:{}
# Make your life a story worth telling
import base64
import hashlib

import matplotlib.pyplot as plt
import numpy as np
from ecdsa import SigningKey,SECP256k1

m = hashlib.md5()
m.update("使用md5加密的数据".encode('utf-8'))

print(m.hexdigest())


# 区块链用的的一些库

s = hashlib.sha256()
s.update("使用SHA256加密的数据".encode('utf-8'))

print(s.hexdigest())

data = '你好，区块链'
result = base64.b16encode(data.encode("utf-8"))
print(result)
text = base64.b64decode(result)
print(text
      )

# 私钥

sk =SigningKey.generate(curve=SECP256k1)
print(sk)
# 公钥
vk = sk.get_verifying_key()
print(vk)
# 生成签名
signature = sk.sign('Something'.encode('utf-8'))
print(signature)
# 验证签名
res = vk.verify(signature, 'Something'.encode('utf-8'))

print(res)
# 生成数据
x = np.linspace(0,2 * np.pi, 50)
# 绘制图表
plt.plot(x,np.sin(x))

# 显示图形
plt.show()