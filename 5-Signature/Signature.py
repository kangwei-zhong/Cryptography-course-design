import GetPrime
import CalFun


class RSA:
    def __init__(self, key_length, exp):
        self.e = exp
        t = 0

        # 大素数生成
        while CalFun.gcd(self.e, t) != 1:
            p = GetPrime.get_prime(key_length // 2)
            q = GetPrime.get_prime(key_length // 2)
            # 求欧拉函数
            t = CalFun.lcm(p - 1, q - 1)

        self.n = p * q
        self.d = CalFun.MulInvMod(self.e, t)    # 求e的乘法逆元d
        self.p, self.q = p, q
        self.d_p = self.d % (p - 1)
        self.d_q = self.d % (q - 1)
        self.q_Inv = CalFun.MulInvMod(q, p)

    def Sign(self, msg: bytes):
        data = CalFun.Byte2Int(msg)
        x = pow(data, self.d_p, self.p)
        y = pow(data, self.d_q, self.q)
        delta = x - y
        if delta < 0:
            delta += self.p
        h = (self.q_Inv * delta) % self.p
        s = (y + self.q * h) % self.n
        return s

    def ver_sign(self, sign: int):
        data = pow(sign, self.e, self.n)
        return CalFun.Int2Byte(data)
