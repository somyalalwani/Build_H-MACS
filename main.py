from p3 import msg_to_binary
from p2 import dec_to_bin
from p6 import Hs,exp,g,p

n = 64

def Hmac(msg, key, iv):
    msg = msg_to_binary(msg)
    msg_len = dec_to_bin(len(msg)).zfill(n)
    
    iv = iv.zfill(n)
    key = key.zfill(n)
    
    ip = ""
    op = ""

    for i in range(0,8):
        op=op+"01011100"
        ip=ip+"00110110"

    ip_xor = dec_to_bin(int(key,2) ^ int(ip,2)).zfill(n)
    result = Hs(ip_xor, iv)
    
    for i in range(0,len(msg),8):
        msg_block = msg[i:i+n]
        if len(msg_block) != n:
            msg_block = msg_block.ljust(n,"0")

        result = Hs(msg_block, result)

    result = Hs(msg_len, result)

    op_xor = dec_to_bin(int(key,2) ^ int(op,2)).zfill(n)
    Hs_temp = Hs(op_xor, iv)
    result = Hs(result, Hs_temp)

    return result

def main():
    text = "testing out HMAC"

    hmac = Hmac(text,"10111" ,"1011110101010101101011")
    print("Text :",text)
    print("Hmac :",hmac)
    print("Length: " + str(len(hmac)))

if __name__ == '__main__':
    main()