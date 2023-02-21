import sys
import requests
from Crypto.Cipher import AES

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


def computeCBCMACHash_oracle(msg: bytes) -> bytes:
    res = requests.get(
        cfg.Q1_CBCMAC_URL, auth=(cfg.usr, cfg.key), params={"msg": msg.hex()}
    )
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        sys.exit(-1)


def computePkcs7Padding_oracle(msg: bytes) -> bytes:
    res = requests.get(
        cfg.Q1_PKCS7_URL, auth=(cfg.usr, cfg.key), params={"msg": msg.hex()}
    )
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        sys.exit(-1)


def getEncryptionCode_oracle() -> bytes:
    res = requests.get(cfg.Q1_ENCRYPTION_CODE_URL, auth=(cfg.usr, cfg.key))
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        sys.exit(-1)


def getEncryptionCodeWithBackdoor_oracle() -> bytes:
    res = requests.get(
        cfg.Q1_ENCRYPTION_CODE_WITH_BACKDOOR_URL,
        auth=(cfg.usr, cfg.key),
    )
    try:
        return bytes.fromhex(res.text)
    except Exception as e:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        sys.exit(-1)


def isValidEncryptionBackdoor_oracle(msg: bytes) -> bool:
    res = requests.get(
        cfg.Q1_IS_VALID_ENCRYPTION_BACKDOOR_URL,
        auth=(cfg.usr, cfg.key),
        params={"msg": msg.hex()},
    )
    if res.text == "true":
        return True
    elif res.text == "false":
        return False
    else:
        print(
            f"Server Error: The server failed to process the request, and produced the following output. Please do not be alarmed and share the output with the TAs on Slack so they can debug the error.\n\n{res.text}"
        )
        sys.exit(-1)


def generate_custom_cbcmac_collision(
    prefix_message: bytes, target_hash: bytes
) -> bytes:
    # TODO: fill in your answer here

    decrypted_hash = AES.new("AAAAAAAAAAAAAAAA".encode(), AES.MODE_CBC, bytes(bytearray(BLOCK_BYTES))).decrypt(target_hash)
    x = AES.new("AAAAAAAAAAAAAAAA".encode(), AES.MODE_CBC, bytes(bytearray(BLOCK_BYTES))).decrypt(xor(decrypted_hash, computePkcs7Padding_oracle(bytes())))

    y = computeCBCMACHash_oracle(prefix_message)
    result = xor(y, x)

    
    
    arr1 = bytearray(computePkcs7Padding_oracle(prefix_message))
    arr2 = bytearray(result)
 
    return bytes(arr1+arr2)


if __name__ == "__main__":

    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    encryption_code = getEncryptionCode_oracle()
    encryption_code_with_backdoor = getEncryptionCodeWithBackdoor_oracle()

    true_hash = computeCBCMACHash_oracle(encryption_code)
    print(f"true_hash:\t\t{true_hash.hex()}")

    valid_encryption_code_with_backdoor = generate_custom_cbcmac_collision(
        encryption_code_with_backdoor,
        true_hash,
    )

    forged_hash = computeCBCMACHash_oracle(valid_encryption_code_with_backdoor)
    print(f"forged_hash:\t\t{forged_hash.hex()}")

    if isValidEncryptionBackdoor_oracle(valid_encryption_code_with_backdoor):
        print("Successfully injected a backdoor!")
    else:
        print("Failed to inject a backdoor!")

