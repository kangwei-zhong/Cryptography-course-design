import Signature
from os import urandom
from hashlib import sha1


send = Signature.RSA(1024, 65537)
print("*************************Signature*************************")
msg = b'All these things have you said of beauty, yet in truth you spoke not of her but of needs unsatisfied, and beauty is not a need but an ecstasy. It is not a mouth thirsting nor an empty hand stretched forth, but rather a heart enflamed and a soul enchanted. It is not the image you would see nor the song you would hear, but rather an image you see though you close your eyes and a song you hear though you shut your ears. It is not the sap within the furrowed bark, nor a wing attached to a claw, but rather a garden for ever in bloom and a flock of angels for ever in flight.'

digest = sha1(msg).digest()

print("哈希值为" + str(digest))



sign = send.Sign(digest)
print("*************************Verify*************************")

print("Signature:" + str(sign))

veri = send.ver_sign(sign)


print("Veri_Signature:" + str(veri))
if veri == digest:
    print("Successfully Verified!")