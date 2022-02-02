from binascii import hexlify
from os import urandom
from typing import Callable, Tuple
from CalCurve import Curve, Point


def KeyGen(randfunc: Callable = None) -> Tuple[int, Point]:
    curve = Curve()
    randfunc = randfunc or urandom
    order_bits = 0
    order = curve.n
    print(curve.n)

    while order > 0:
        order >>= 1
        order_bits += 1

    order_bytes = (order_bits + 7) // 8
    extra_bits = order_bytes * 8 - order_bits       # 去除多余的比特位

    na = int(hexlify(randfunc(order_bytes)), 16)    # 产生一个随机的秘密钥na
    na >>= extra_bits

    while na >= curve.n:
        na = int(hexlify(randfunc(order_bytes)), 16)
        na >>= extra_bits

    public_key = na * curve.G()             # p = na*G作为公开钥
    return na, public_key, curve.G()
