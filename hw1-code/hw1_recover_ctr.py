import requests

import config as cfg


def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f"xor given bytes of unequal length. {len(a)=} {len(b)=}"
    return bytes(a ^ b for a, b in zip(a, b))


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def ctr_encryption_oracle(pt: bytes) -> bytes:
    res = requests.get(cfg.CTR_URL, auth=(cfg.usr, cfg.key), params={"pt": pt.hex()})
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def recover_flag() -> bytes:
    flag = bytes()

    # TODO: fill in your answer here

    # testing with two messages whose difference in length is the size of the flag aka 9
    pt1 = b"AAAAAAAAAAAAAAAAA"
    pt2 = b"AAAAAAAA"
    
    # here we are XORing the first plaintext with the ciphertext minus the flag, and XORing that with the second ciphertext 
    flag = xor(xor(pt1,ctr_encryption_oracle(pt1)[:len(pt1)]),ctr_encryption_oracle(pt2))
    
    # which returns the second plaintext and then we can just get the last 9 bytes which is the flag
    return flag[-9:]


if __name__ == "__main__":
    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    flag = recover_flag()
    print(flag.decode())
