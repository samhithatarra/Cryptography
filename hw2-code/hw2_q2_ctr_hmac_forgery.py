import requests
import requests_cache
import time
import itertools
import config as cfg
import hashlib
import string
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


def genCookie_oracle() -> bytes:
    res = requests.get(cfg.Q2_GENCOOKIE_URL, auth=(cfg.usr, cfg.key))
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def isCookieAdFree_oracle(ct: bytes) -> bool:
    res = requests.get(
        cfg.Q2_ADFREE_URL, auth=(cfg.usr, cfg.key), params={"ct": ct.hex()}
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


def gen_cookie_ad_free() -> bytes:
    timestamp = "0" * 10
    generated_cookie_arr = bytearray(genCookie_oracle())
    nonce = generated_cookie_arr[0:BLOCK_BYTES]
    nonceless_gen_cookie = generated_cookie_arr[BLOCK_BYTES:]
    alphabet_num = ["a","b","c","d","e","f","1","2","3","4","5","6","7","8","9","0"]

    trunc_possibilities = list(itertools.permutations(alphabet_num, 2))

    print(len(list(trunc_possibilities)))
    # print(len(trunc_possibilities))

    for i in range(len(trunc_possibilities)):
        
        trunc1 = ""
        trunc1+= trunc_possibilities[i][0] +trunc_possibilities[i][1]
        print("TRUCN1" ,trunc1)
        
        full_ad_txt = "username={}&validtill={}&adfree=0&hmacsha256={}".format(cfg.usr,timestamp,trunc1)
        for j in range(len(trunc_possibilities)):
            trunc2 = ""
            trunc2+= trunc_possibilities[j][0] +trunc_possibilities[j][1]
            print(trunc2)
            full_adfree_txt = "username={}&validtill={}&adfree=1&hmacsha256={}".format(cfg.usr,timestamp,trunc2)
            
            pad = xor(nonceless_gen_cookie, full_ad_txt.encode())
            
            forged = xor(pad, full_adfree_txt.encode())
            
            forged_final = bytes(nonce + forged )
            if isCookieAdFree_oracle(forged_final) == True:
                print(full_adfree_txt)
                print("WE DID IT")
                return(forged_final)
            
    return genCookie_oracle()


if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    cookie_ad_free = gen_cookie_ad_free()
    if isCookieAdFree_oracle(cookie_ad_free):
        print("Forged AdFree cookie ciphertext:", cookie_ad_free.hex())
    else:
        print("Failed to forge AdFree cookie ciphertext")
