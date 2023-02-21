import requests
import secrets
import copy
from datetime import timedelta

import config as cfg

BLOCK_BYTES = 16


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f"xor given bytes of unequal length. {len(a)=} {len(b)=}"
    return bytes(a ^ b for a, b in zip(a, b))


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def encrypt_oracle() -> bytes:
    res = requests.get(cfg.Q3_ENCRYPT_URL, auth=(cfg.usr, cfg.key))
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def check_padding_oracle(ct: bytes) -> bool:
    res = requests.get(
        cfg.Q3_PADDING_URL, auth=(cfg.usr, cfg.key), params={"ct": ct.hex()}
    )
    if res.text == "true":
        return True
    elif res.text == "false":
        return False
    else:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)




def recover_flag() -> bytes:
    flag = bytes()

    # TODO: fill in your answer here
    # https://blog.skullsecurity.org/2013/a-padding-oracle-example <- used this to help me understand the math behind the XORS
    # P2 = decrypted
    # P′2 = pad
    # C′ = brute_val / rand
    # C1 = iv

    ciphertext = bytearray(encrypt_oracle())
    iv = ciphertext[:BLOCK_BYTES]    
    c1 = ciphertext[BLOCK_BYTES:]
    print("CIPHERTEXT", ciphertext.hex())
    print("IV", iv.hex())
    print("BLOCK1", c1.hex())

    pad = 1
    decrypted = bytearray(BLOCK_BYTES)
    rand = bytearray(BLOCK_BYTES)
    for i in range(1,BLOCK_BYTES+1):
        # brute force here
        for brute_val in range(0xFF):
            rand[-pad] = brute_val
            test = rand + c1
            # check for true from oracle
            if check_padding_oracle(test) == True:
                # store the recovered byte
                decrypted[-pad] = pad ^ brute_val ^ iv[-i]
                # adjust padding for the next round
                for k in range(1, pad+1):
                    rand[-k] = pad+1 ^ decrypted[-k] ^ iv[-k]
                break       
        
        pad+=1
        print(decrypted)
    print(decrypted)
    flag = decrypted
        
    return flag 


if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    flag = recover_flag()
    print(flag.decode())
