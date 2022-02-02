import CalFun
from key import KeyGen
from Elgamal import ElGamal


def test():
    pri_key, pub_key, gen = KeyGen()
    c1 = []
    c2 = []
    gl = []

    m = "All these things have you said of beauty, yet in truth you spoke not of her but of needs unsatisfied, and beauty is not a need but an ecstasy. It is not a mouth thirsting nor an empty hand stretched forth, but rather a heart enflamed and a soul enchanted. It is not the image you would see nor the song you would hear, but rather an image you see though you close your eyes and a song you hear though you shut your ears. It is not the sap within the furrowed bark, nor a wing attached to a claw, but rather a garden for ever in bloom and a flock of angels for ever in flight."
    print("\nThe message is \n" + m )
    print("****** KeyGeneration ******\n")
    print("Private key:" + str(pri_key))
    print("Public key:" + str(pub_key))
    print("Generate G:" + str((gen)))
    mlist = CalFun.cut(m.encode('utf-8'), 25)   # 分组长度25
    for i in mlist:
        u, v, g = ElGamal(pub_key.curve).Encryption(i, pub_key)
        c1.append(u)
        c2.append(v)
        gl.append(g)
    print("****** Encryption ******\n")
    print("Cipher:" + str(c1) + str(c2))
    print("b = " + str(gl) + "\n")
    print('Finish Encryption!\n')

    de_mlist = []
    print("****** Decryption ******\n")
    for u, v in zip(c1, c2):
        de_m = ElGamal(pub_key.curve).Decryption(pri_key, u, v).decode('utf-8')
        de_mlist.append(str(de_m))

    decrypted_msg = ''.join(de_mlist)
    print("Decrypted cipher:\n" + decrypted_msg)
    print('Finish Decryption!\n')


if __name__ == "__main__":
    test()
