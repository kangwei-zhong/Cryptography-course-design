import random
from os import urandom
from typing import Callable, Tuple
from dataclasses import dataclass
from CalCurve import Curve, Point


@dataclass
class ElGamal:
    curve: Curve
    k: int
    
    def __init__(self, curve: Curve) -> None:
        self.curve = curve
        self.k = random.randint(1, self.curve.n)

    def Encryption(self, plaintext: bytes, public_key: Point,
                randfunc: Callable = None) -> Tuple[Point, Point]:  # 调用对点加密的函数
        m = self.curve.encode_point(plaintext)
        return self.EnPoint(m, public_key, randfunc)

    def Decryption(self, private_key: int, C1: Point, C2: Point) -> bytes:
        m = self.DePoint(private_key, C1, C2)    # 调用对点解密的函数
        return self.curve.decode_point(m)

    def EnPoint(self, plaintext: Point, public_key: Point,
                      randfunc: Callable = None) -> Tuple[Point, Point]:
        randfunc = randfunc or urandom
        G = self.curve.G
        m = plaintext
        random.seed(randfunc(1024))
        k = self.k
        C1 = k * G()
        C2 = m + k * public_key         # 产生密文点对{kG, m + k*Pa}
        return C1, C2, k

    def DePoint(self, private_key: int, c1: Point, c2: Point) -> Point:
        M = c2 + (self.curve.n - private_key) * c1
        return M
