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

def legendre_symbol(a, p):
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls

def ModSqrt(a, p):
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m

def int_length_in_byte(n: int):
    assert n >= 0
    length = 0
    while n:
        n >>= 8
        length += 1
    return length

def cut(obj, sec):
    return [obj[i:i+sec] for i in range(0,len(obj),sec)]