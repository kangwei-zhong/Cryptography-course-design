from os import urandom
from dataclasses import dataclass
from typing import Optional
import CalFun


@dataclass
class Point:
    x: Optional[int]
    y: Optional[int]
    curve: "Curve"

    def is_inf(self) -> bool:   # 判断是不是无穷远点
        return self.x is None and self.y is None

    def __eq__(self, other):    # 判椭圆上的点是否相等
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    def __neg__(self):          # 判断是不是加法逆元
        return self.curve.neg_point(self)

    def __add__(self, other):   # 椭圆点加
        return self.curve.add_point(self, other)

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):   # 椭圆点减
        negative = - other
        return self.__add__(negative)

    def __mul__(self, scalar: int):     # 椭圆点乘
        return self.curve.mul_point(scalar, self)

    def __rmul__(self, scalar: int):
        return self.__mul__(scalar)

    def x(self):    # 获取x点
        return self.x

    def y(self):    # 获取y点
        return self.y

    def curve(self):    # 获取椭圆
        return self.curve


class Curve:
    def __init__(self):     # 参数设置，Secp256k1的参数
        self.judge = "OnCurve"
        self.a = 0
        self.b = 7
        self.p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
        self.n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
        self.Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
        self.Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

    def __str__(self):
        return self.judge

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return (
            self.a == other.a and self.b == other.b and self.p == other.p and
            self.n == other.n and self.Gx == other.Gx and self.Gy == other.Gy
        )

    def G(self) -> Point:
        return Point(self.Gx, self.Gy, self)

    def INF(self) -> Point:
        return Point(None, None, self)

    def is_on_curve(self, p: Point) -> bool:
        if p.curve != self:
            return False
        left = p.y * p.y
        right = (p.x * p.x * p.x) + (self.a * p.x) + self.b
        return p.is_inf() or (left - right) % self.p == 0

    def add_point(self, p: Point, q: Point) -> Point:
        if p.is_inf():
            return q
        elif q.is_inf():
            return p
        if p == q:
            return self.double_point(p)
        if p == -q:
            return self.INF
        delta_x = p.x - q.x
        delta_y = p.y - q.y
        s = delta_y * CalFun.MulInvMod(delta_x, self.p)  # 求λ，用到乘法逆元
        res_x = (s * s - p.x - q.x) % self.p    # x3 = λ^2 - x1 - x2
        res_y = (p.y + s * (res_x - p.x)) % self.p
        return - Point(res_x, res_y, self)

    def double_point(self, p: Point) -> Point:
        if p.is_inf():
            return self.INF
        s = (3 * p.x * p.x + self.a) * CalFun.MulInvMod(2 * p.y, self.p)
        res_x = (s * s - 2 * p.x) % self.p
        res_y = (p.y + s * (res_x - p.x)) % self.p
        return - Point(res_x, res_y, self)

    def mul_point(self, d: int, p: Point) -> Point:
        if p.is_inf():      # 无穷远点的倍数为其本身
            return self.INF
        if d == 0:          # 乘以0倍也是无穷远点
            return self.INF

        res = None
        judge = d < 0
        d = abs(d)
        tmp = p
        while d:
            if d & 0x1 == 1:    # 为奇数
                if res:
                    res = self.add_point(res, tmp)
                else:           # 为偶数
                    res = tmp
            tmp = self.double_point(tmp)
            d >>= 1
        if judge:
            return -res
        else:
            return res

    def neg_point(self, p: Point) -> Point:
        if p.is_inf():
            return self.INF
        return Point(p.x, -p.y % self.p, self)

    def compute_y(self, x: int) -> int:
        right = (x * x * x + self.a * x + self.b) % self.p
        y = CalFun.ModSqrt(right, self.p)
        return y

    def encode_point(self, m: bytes) -> Point:      # 将明文嵌入到椭圆曲线的点上
        m = len(m).to_bytes(1, byteorder="big") + m
        while True:
            x = int.from_bytes(m, "big")
            y = self.compute_y(x)
            if y:
                return Point(x, y, self)
            m += urandom(1)

    def decode_point(self, m: Point) -> bytes:      # 将嵌入椭圆曲线的点还原
        byte_len = CalFun.int_length_in_byte(m.x)
        mlen = (m.x >> ((byte_len - 1) * 8)) & 0xff
        de_m = ((m.x >> ((byte_len - mlen - 1) * 8)) & (int.from_bytes(b"\xff" * mlen, "big")))
        return de_m.to_bytes(mlen, byteorder="big")
