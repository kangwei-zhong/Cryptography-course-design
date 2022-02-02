from random import randrange


# 大素数生成

def generate_odd(n):
    assert n > 1    # n > 1正常运行
    return randrange(2 ** (n - 1) + 1, 2 ** n, 2)   # 步长为2， 保证是奇数


primes_list = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31,37, 41, 43, 47, 53, 59, 61, 67, 71, 73,79, 83, 89, 97, 101, 103, 107, 109, 113, 127,131, 137, 139, 149, 151, 157, 163, 167, 173, 179,181, 191, 193, 197, 199, 211, 223, 227, 229, 233]


def first_prime_test(n):
    while True:
        r = generate_odd(n)
        for num in primes_list:
            if r % num == 0 and num ** 2 <= r:
                break
            else:
                return r


def miller_rabin_prime_test(n):
    assert n > 3
    if n % 2 == 0:
        return False
    s = 0
    d = n - 1
    while d % 2 == 0:
        d = d >> 1
        s += 1
    k = 20
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def get_prime(n):
    while True:
        p = first_prime_test(n)
        if miller_rabin_prime_test(p):
            return p

