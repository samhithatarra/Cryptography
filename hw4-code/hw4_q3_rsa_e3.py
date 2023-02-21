import base64
import binascii
import hashlib    
import requests
import time
import os

import config as cfg
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from sympy import root

MAX_BYTE_LENGTH = 2048 // 8
Sha256AlgorithmId = (
    b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
)


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def getPkAndMsg_oracle():
    res = requests.get(cfg.Q3_GETMSG_URL, auth=(cfg.usr, cfg.key))
    try:
        res_dict = res.json()
        N = int.from_bytes(bytes.fromhex(res_dict["N"]), "big")
        msg = bytes.fromhex(res_dict["Message"])
        return N, msg
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}\n\n{e}"
        )
        exit(-1)


def verifyRSA_oracle(sig: int) -> bool:
    res = requests.get(
        cfg.Q3_VERIFYRSA_URL,
        auth=(cfg.usr, cfg.key),
        params={"Signature": sig.to_bytes(MAX_BYTE_LENGTH, "big").hex()},
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






def forge_signature() -> int:
    N, msg = getPkAndMsg_oracle()

    # TODO: fill in your answer here

    hashedmsg = SHA256.new()
    hashedmsg.update(msg)
    hashedmsg = hashedmsg.digest()

    suffix = b'\x00' + Sha256AlgorithmId + hashedmsg
    
    f_padding = bytearray(MAX_BYTE_LENGTH - 2 - len(suffix))
    for i in range(len(f_padding)):
        f_padding[i] = 0xFF

    prefix = b'\x00\x01'

    d = int.from_bytes(prefix + bytes(f_padding) + suffix, 'big')
 
    cubed = int(root(d, 3))
   
    if d != cubed**3:
        cubed+=1
        junk = cubed**3 - d
    
        d = int.from_bytes(prefix + suffix + junk.to_bytes(MAX_BYTE_LENGTH - 2 - len(suffix), 'big'), 'big')


    return int(root(d, 3))


if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    sig = forge_signature()
    if verifyRSA_oracle(sig) == True:
        print("Successfully forged a valid signature!")
    else:
        print("Failed to forge a valid signature!")
