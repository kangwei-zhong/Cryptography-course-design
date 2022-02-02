def gcd(a, b):
    while b:
        a, b = b, a % b
    return a



def lcm(a, b):
    return a * b // gcd(a, b)



def Extend_Euclid(a, b):  # 返回的是gcd， s， t
    s1 = 1
    s2 = 0
    t1 = 0
    t2 = 1
    while b:
        q = a // b
        s2, s1 = s1 - q * s2, s2
        t2, t1 = t1 - q * t2, t2
        a, b = b, a % b
    return a, s1, t1



# 求乘法逆元
def MulInvMod(e, m):
    gcd, x, y = Extend_Euclid(e, m)
    assert gcd == 1
    if x < 0:
        x += m
    return x


def Int2Byte(n):
    if n == 0:
        return bytes(1)
    return n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")   # 要规定大端


def Byte2Int(n):
    return int.from_bytes(n, byteorder="big")   # 规定大端方式

