import requests
import time

import config as cfg
import hmac as opaque_hmac


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def getData_oracle() -> bytes:
    res = requests.get(cfg.Q3_GETDATA_URL, auth=(cfg.usr, cfg.key))
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        exit(-1)


def checkHMAC_oracle(msg: bytes) -> bool:
    return opaque_hmac.checkHMAC(msg)


def forge_tag() -> bytes:
    # TODO: fill in your answer here
    data = getData_oracle()
    hmac = bytearray(4)
    searching = True

    while searching:
        for i in range(1,5):
            if checkHMAC_oracle(data + bytes(hmac)) == True:
                searching = False

            for possibility in range(0, 256):
                hmac[i-1] = possibility
                pre_time = time.time()
                checkHMAC_oracle(data + bytes(hmac))
                post_time = time.time()

                if post_time - pre_time > (i * 0.02):
                    break
        

    return data + bytes(hmac)
    


if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    msg = forge_tag()
    if checkHMAC_oracle(msg) == True:
        print("Successfully forged a valid tag!")
    else:
        print("Failed to forge a valid tag!")
