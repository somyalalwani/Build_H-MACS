exp = 227
g = 47
p = 27527
from p2 import dec_to_bin

def Hs(x1, x2, exp = exp):
    h = pow(g, exp, p)  #pow(x, y, z) is equal to g^exp % p

    hash = (pow(g, int(x1,2), p) * pow(h, int(x2,2), p)) % p # (g^x1 % p) * (((g^exp % p)^x2 % p)) %p
    return dec_to_bin(hash).zfill(64)
