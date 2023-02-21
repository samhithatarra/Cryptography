import requests
import requests_cache

import config as cfg
import pymd5

BLOCK_BYTES = 64
MD5_BYTES = 16


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


def isCookieAdFree_oracle(cookie: bytes) -> bool:
    res = requests.get(
        cfg.Q2_ADFREE_URL, auth=(cfg.usr, cfg.key), params={"cookie": cookie.hex()}
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


def padding(msg_len_in_bytes: int) -> bytes:
    return pymd5.padding(msg_len_in_bytes * 8)


def md5_compress(state: bytes, block: bytes) -> bytes:
    assert len(block) == BLOCK_BYTES, f"block size not equal to 64 bytes"
    assert len(state) == MD5_BYTES, f"state size not equal to 16 bytes"
    decoded = pymd5._decode(state, MD5_BYTES)
    return pymd5._encode(
        pymd5.md5_compress(pymd5._decode(state, MD5_BYTES), block), MD5_BYTES
    )


def gen_cookie_ad_free() -> bytes:
    timestamp = "0" * 10

    # TODO: fill in your answer here

    generated_cookie = genCookie_oracle()  

    ad_txt = "username={}&validtill={}&adfree=0".format(cfg.usr,timestamp)
    state = bytes.fromhex(generated_cookie.decode().split("=")[-1])


    for secret_len in range(16, 65):

        padded_ad_txt = ad_txt.encode() + padding(secret_len + len(ad_txt))
        md5_len = secret_len + len(padded_ad_txt)
    
        block = b'&adfree=1' + padding(md5_len + len(b'&adfree=1'))

        md5 = md5_compress(state, block).hex().encode()
        ad_free_cookie = padded_ad_txt + b'&adfree=1&md5=' + md5

        if isCookieAdFree_oracle(ad_free_cookie):
            return ad_free_cookie
        

    return genCookie_oracle()

if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    ad_free_cookie = gen_cookie_ad_free()
    if isCookieAdFree_oracle(ad_free_cookie) == True:
        print("Successfully forged AdFree cookie!")
    else:
        print("Failed to forge adFree cookie!")
