# Opaque implementation of hmac
# DO NOT MODIFY / WILL BE SUBBED FOR GRADING

import time
import config as cfg
from Crypto.Hash import HMAC, SHA256


def superSlowMemcmp(str1: bytes, str2: bytes, n: int) -> bool:
    if (len(str1) < n) or (len(str2) < n):
        raise Exception("input too short")

    for i in range(n):
        if str1[i] != str2[i]:
            return False
        time.sleep(0.02)

    return True


def checkHMAC(msg: bytes) -> bool:
    data = msg[: len(msg) - 4]
    tag = msg[len(msg) - 4 :]

    h = HMAC.new(cfg.Q3_SECRET, digestmod=SHA256)
    h.update(data)
    hmac = h.digest()

    res = superSlowMemcmp(tag, hmac, 4)
    return res
