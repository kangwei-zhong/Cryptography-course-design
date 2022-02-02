import GetPrime
import CalFun


class RSA:
    def __init__(self, key_length, exp):
        self.e = exp
        t = 0

        while CalFun.gcd(self.e, t) != 1:
            p = GetPrime.get_prime(key_length // 2)
            q = GetPrime.get_prime(key_length // 2)
            t = CalFun.lcm(p - 1, q - 1)

        self.n = p * q
        self.d = CalFun.MulInvMod(self.e, t)

        self.p, self.q = p, q
        self.d_p = self.d % (p - 1)
        self.d_q = self.d % (q - 1)
        self.q_Inv = CalFun.MulInvMod(q, p)


    def Encryption(self, m):
        data = CalFun.Byte2Int(m)
        return pow(data, self.e, self.n)


    def Decryption(self, c):
        data = pow(c, self.d, self.n)
        m1 = pow(c, self.d_p, self.p)
        m2 = pow(c, self.d_q, self.q)
        t = m1 - m2
        if t < 0:
            t = t + self.p
        h = (self.q_Inv * t) % self.p
        m = (m2 + h * self.q) % self.n
        return CalFun.Int2Byte(m)

