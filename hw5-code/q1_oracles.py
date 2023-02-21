import collections

import Crypto
from Crypto.Cipher import AES

CiphertextWithTag = collections.namedtuple("CiphertextWithTag", ["ciphertext", "tag"])
DecryptionContext = collections.namedtuple("DecryptionContext", ["key", "nonce"])

KEY = bytes([i for i in range(16)])


def getKeyNonceMessage_oracle() -> (bytes, bytes, bytes):
    key = KEY
    nonce = Crypto.Random.get_random_bytes(12)
    message = Crypto.Random.get_random_bytes(32)
    return key, nonce, message


def verifyCollision_oracle(
    ciphertextWithTag: CiphertextWithTag,
    context1: DecryptionContext,
    context2: DecryptionContext,
) -> bool:
    if context1.key != KEY:
        print(
            "The key in the context1 should be the key output by the getKeyNonceMessage oracle."
        )
        return False
    # Try decrypting with the first context
    try:
        cipher1 = AES.new(context1.key, AES.MODE_GCM, nonce=context1.nonce)
        msg = cipher1.decrypt_and_verify(
            ciphertextWithTag.ciphertext, ciphertextWithTag.tag
        )
    except ValueError as e:
        print(f"Decryption under first context failed with error: {e}")
        return False
    # Try decrypting with the second context
    try:
        cipher2 = AES.new(context2.key, AES.MODE_GCM, nonce=context2.nonce)
        msg = cipher2.decrypt_and_verify(
            ciphertextWithTag.ciphertext, ciphertextWithTag.tag
        )
    except ValueError as e:
        print(f"Decryption under second context failed with error: {e}")
        return False

    return True
