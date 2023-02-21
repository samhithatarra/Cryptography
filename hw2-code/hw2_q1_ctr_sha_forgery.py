from re import fullmatch
import requests
import requests_cache
import time
import config as cfg
import hashlib

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


def sha256(data: bytes) -> bytes:
    m = hashlib.sha256()
    m.update(data)
    return m.hexdigest()


def genCookie_oracle() -> bytes:
    res = requests.get(cfg.Q1_GENCOOKIE_URL, auth=(cfg.usr, cfg.key))
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def isCookieAdFree_oracle(ct: bytes) -> bool:
    res = requests.get(
        cfg.Q1_ADFREE_URL, auth=(cfg.usr, cfg.key), params={"ct": ct.hex()}
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
    # TODO: fill in your answer here

    generated_cookie_arr = bytearray(genCookie_oracle())
    nonce = generated_cookie_arr[0:16]
    nonceless_gen_cookie = generated_cookie_arr[16:]
    
    curr60 = time.time() + 3600
    print(time.ctime(time.time()))
    time_vals = [curr60]

    for i in range(1,60):
        time_vals.append(curr60+i)
        time_vals.append(curr60-i)
        
    
    for t in time_vals:

        t = str(t).split('.')[0]
        ad_txt = "username={}&validtill={}&adfree=0".format(cfg.usr,t)
        adfree_txt = "username={}&validtill={}&adfree=1".format(cfg.usr,t)

        # the sha value getting tacked on 
        hashed_ad = sha256(ad_txt.encode())
        hashed_adfree = sha256(adfree_txt.encode())
        

        full_ad_txt = "username={}&validtill={}&adfree=0&sha256={}".format(cfg.usr,t,hashed_ad)
        full_adfree_txt = "username={}&validtill={}&adfree=1&sha256={}".format(cfg.usr,t,hashed_adfree)

        
        
        pad = xor(nonceless_gen_cookie, full_ad_txt.encode())
        forged = xor(pad, full_adfree_txt.encode())

        forged_final = bytes(nonce + forged)
        if isCookieAdFree_oracle(forged_final) == True:
            print(full_adfree_txt)
            print("WE DID IT")
            return(forged_final)
        else:
            print("False")


        
    return bytes()


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
