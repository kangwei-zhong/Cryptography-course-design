import RSA
from os import urandom
from timeit import timeit
send = RSA.RSA(1024, 65537)
msg = b'I love Cryptography'
print("\nThe message is \n" + "I love Cryptography" )
print("****** Encryption ******\n")
c = send.Encryption(msg)
print("Cipher:" + str(c))
print('Finish Encryption!\n')
print("****** Decryption ******\n")
msg2 = send.Decryption(c)
print("Decrypted cipher:" )
print(msg2)
print('Finish Decryption!\n')

print("****** Performance Analysis ******\n")


for len in [512, 1024, 2048, 4096]:
    send = RSA.RSA(len, 65537)
    t = 0
    for _ in range(5):
        msg = urandom(int(len / 16))
        c = send.Encryption(msg)
        t += timeit(lambda: send.Decryption(c), number=int(len ** 0.5))
    print("KeySize: %4d time: %.4fs" %(len, t/5/int(len / 16)))