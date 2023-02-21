import collections
import requests
import requests_cache
import bitstring
from sympy import mod_inverse
from ecdsa import SigningKey, NIST256p
from hashlib import sha256

import config as cfg

ECDSASignature = collections.namedtuple("ECDSASignature", ["r", "s"])

MAX_BYTE_LENGTH = 256 // 8
CURVE = NIST256p
N = NIST256p.generator.order()
MESSAGE = ("Hello from " + cfg.usr).encode()


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def getSignature_oracle() -> (bytes, ECDSASignature):
    res = requests.get(cfg.Q1_GET_SIGNATURE, auth=(cfg.usr, cfg.key))
    try:
        res_dict = res.json()
        msg = bytes.fromhex(res_dict["Message"])
        r = int.from_bytes(bytes.fromhex(res_dict["R"]), "big")
        s = int.from_bytes(bytes.fromhex(res_dict["S"]), "big")
        return msg, ECDSASignature(r, s)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}\n\n{e}"
        )
        exit(-1)


def verifySignature_oracle(sig: ECDSASignature) -> bool:
    res = requests.get(
        cfg.Q1_VERIFY_SIGNATURE,
        auth=(cfg.usr, cfg.key),
        params={
            "R": sig.r.to_bytes(MAX_BYTE_LENGTH, "big").hex(),
            "S": sig.s.to_bytes(MAX_BYTE_LENGTH, "big").hex(),
        },
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

    
    
def recover_secret_key() -> int:
    # TODO: fill in your answer here
    
    nonce_reused_check = dict()
    # can iterate how many ever times we want here but because there is a high probability the nonce is reused it most likely will
    # find the reused nonce way sooner than actually having to go through this loop 100 times
    for i in range(100):
        m, (r, s) = getSignature_oracle()
        print(nonce_reused_check)
        
        for k,v in nonce_reused_check.items():
            # actual attack meaning we found a reused nonce
            if r in v:
                if k != m:
                    m1 = m
                    s1 = s
                    m2 = k
                    s2 = v[1]

                    hash_m1 = sha256(m1).hexdigest()
                    L1 = int(hash_m1, 16)

                    
                    hash_m2 = sha256(m2).hexdigest()
                    L2 = int(hash_m2, 16)

                    # sk = numerator * denominator % N
                    return (((s2*L1) % N) - ((s1*L2) % N)) * mod_inverse(r * ((s1 - s2) % N), N) % N

        else:
            # adding the info to our dict so we can cross check 
            nonce_reused_check[m] = [r,s]
            
    

    


def forge_signature(msg) -> ECDSASignature:
    secret_key = recover_secret_key()
    sk = SigningKey.from_secret_exponent(secret_key, curve=CURVE, hashfunc=sha256)
    hashHex = sha256(msg).hexdigest()
    hashInt = int.from_bytes(bytes.fromhex(hashHex), "big")
    r, s = sk.sign_number(hashInt)
    return ECDSASignature(r, s)


if __name__ == "__main__":
    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    sig = forge_signature(MESSAGE)
    if verifySignature_oracle(sig) == True:
        print("Successfully forged a valid signature!")
    else:
        print("Failed to forge a valid signature!")
