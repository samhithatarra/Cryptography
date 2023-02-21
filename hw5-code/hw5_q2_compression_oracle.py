import requests
import sys

import config as cfg


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def compressThenEncrypt_oracle(msg: bytes) -> bytes:
    res = requests.get(
        cfg.Q2_COMPRESS_ENCRYPT, auth=(cfg.usr, cfg.key), params={"msg": msg.hex()}
    )
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        sys.exit(-1)


def recover_flag() -> bytes:
    flag = bytes()

    # TODO: fill in your answer here
    possibilties = "abcdef1234567890}"
    msg = "ZLIB{"
    # print(len(compressThenEncrypt_oracle(msg)))
    not_done = True
    
    while not_done:
        length = len(compressThenEncrypt_oracle(msg.encode()))
        for i in possibilties:
            temp_msg = msg + i
            res = compressThenEncrypt_oracle(temp_msg.encode())
            if len(res) == length:
                length = len(res)
                msg = temp_msg
                if i == "}":
                    not_done = False
                    flag = msg.encode()
        

    return flag


if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    flag = recover_flag()
    print(flag.decode())
