import requests

import Crypto
from Crypto.Cipher import AES

import config as cfg
import gf128
from q1_oracles import (
    verifyCollision_oracle,
    getKeyNonceMessage_oracle,
    CiphertextWithTag,
    DecryptionContext,
)


def check_auth():
    res = requests.get(cfg.AUTH_URL, auth=(cfg.usr, cfg.key))
    if res.text != f"auth succeeded for {cfg.usr}":
        raise Exception(
            f"failed to authenticate with the server\nplease ensure that you set the username and API key correctly in the python script\n\ngot error: {res.text}\n"
        )


def aes128_encrypt(key: bytes, data: bytes) -> bytes:
    if len(key) != 16:
        raise Exception(f"Invalid key size, expected 16 bytes, got {len(data)} bytes")
    if len(data) != 16:
        raise Exception(f"Invalid data size, expected 16 bytes, got {len(data)} bytes")
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(data)
    return ciphertext


def aes128_decrypt(key: bytes, data: bytes) -> bytes:
    if len(key) != 16:
        raise Exception(f"Invalid key size, expected 16 bytes, got {len(data)} bytes.")
    if len(data) != 16:
        raise Exception(f"Invalid data size, expected 16 bytes, got {len(data)} bytes.")
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.decrypt(data)
    return ciphertext


def compute_gcm_collision() -> (
    CiphertextWithTag,
    DecryptionContext,
    DecryptionContext,
):
    """
    Compute a ciphertext and two valid decryption contexts for it.
    """
    # Encrypt the given message under the given key and nonce.
    key1, nonce, original_message = getKeyNonceMessage_oracle()
    cipher = AES.new(key1, AES.MODE_GCM, nonce=nonce)
    original_ciphertext, _ = cipher.encrypt_and_digest(original_message)

    # Pick an arbitrary second key.
    key2 = bytes([0 for _ in range(15)]) + bytes([2])

    # Initialize interal variables
    # See Collide-GCM in Figure 2 of https://eprint.iacr.org/2019/016.pdf
    Na = nonce + bytes([0 for _ in range(4)])
    H1 = aes128_encrypt(key1, bytes([0 for _ in range(16)]))
    H2 = aes128_encrypt(key2, bytes([0 for _ in range(16)]))
    P1 = aes128_encrypt(key1, gf128.add(Na, gf128.ONE))
    P2 = aes128_encrypt(key2, gf128.add(Na, gf128.ONE))

    # Split into 4 GHASH blocks
    # We are solving for C2
    C0 = original_ciphertext[0:16]
    C1 = original_ciphertext[16:32]
    C2 = None
    C3 = (3 * 16 * 8).to_bytes(16, byteorder="big")  # length block

    # Following https://keymaterial.net/2020/09/07/invisible-salamanders-in-aes-gcm-siv/
    # C2 = (H1^2 + H2^2)^(-1) • [C0•(H1^4 + H2^4) + C1•(H1^3+H2^3) + C3•(H1+H2) + P1 + P2]

    # TODO: fill in your answer here, specifically compute C2.
    
    c2_1 = gf128.add(gf128.multiply(C0,(gf128.add(gf128.pow(H1,4),gf128.pow(H2,4)))), gf128.multiply(C1,(gf128.add(gf128.pow(H1,3),gf128.pow(H2,3)))))
    c2_2 = gf128.add(gf128.multiply(C3,gf128.add(H1,H2)),gf128.add(P1,P2))
    C2 = gf128.add(c2_1,c2_2)
    C2 = gf128.multiply(gf128.inverse(gf128.add(gf128.square(H1),gf128.square(H2))),C2)
    
    
    print("HERE IS C2", C2)


    ciphertext = C0 + C1 + C2

    # Following https://keymaterial.net/2020/09/07/invisible-salamanders-in-aes-gcm-siv/
    # tag1 = C0•H1^4 + C1•H1^3 + C2•H1^2 + C3•H1 + P1
    # tag2 = C0•H2^4 + C1•H2^3 + C2•H2^2 + C3•H2 + P2
    # If we did everything correctly, the tag values should match.
    tag1 = P1
    tag1 = gf128.add(tag1, gf128.multiply(C3, gf128.pow(H1, 1)))
    tag1 = gf128.add(tag1, gf128.multiply(C2, gf128.pow(H1, 2)))
    tag1 = gf128.add(tag1, gf128.multiply(C1, gf128.pow(H1, 3)))
    tag1 = gf128.add(tag1, gf128.multiply(C0, gf128.pow(H1, 4)))

    tag2 = P2
    tag2 = gf128.add(tag2, gf128.multiply(C3, gf128.pow(H2, 1)))
    tag2 = gf128.add(tag2, gf128.multiply(C2, gf128.pow(H2, 2)))
    tag2 = gf128.add(tag2, gf128.multiply(C1, gf128.pow(H2, 3)))
    tag2 = gf128.add(tag2, gf128.multiply(C0, gf128.pow(H2, 4)))

    assert tag1 == tag2
    tag = tag1

    # Now, for a final check, compute the corresponding plaintexts and verify
    # that, on encryption, the tags match the one we generated.
    msg1 = (
        gf128.add(C0, aes128_encrypt(key1, gf128.add(Na, gf128.TWO)))
        + gf128.add(C1, aes128_encrypt(key1, gf128.add(Na, gf128.THREE)))
        + gf128.add(C2, aes128_encrypt(key1, gf128.add(Na, gf128.FOUR)))
    )
    assert msg1[0:32] == original_message
    msg2 = (
        gf128.add(C0, aes128_encrypt(key2, gf128.add(Na, gf128.TWO)))
        + gf128.add(C1, aes128_encrypt(key2, gf128.add(Na, gf128.THREE)))
        + gf128.add(C2, aes128_encrypt(key2, gf128.add(Na, gf128.FOUR)))
    )

    cipher = AES.new(key1, AES.MODE_GCM, nonce=nonce)
    new_ciphertext1, new_tag1 = cipher.encrypt_and_digest(msg1)
    cipher = AES.new(key2, AES.MODE_GCM, nonce=nonce)
    new_ciphertext2, new_tag2 = cipher.encrypt_and_digest(msg2)

    assert tag == new_tag1
    assert tag == new_tag2
    assert ciphertext == new_ciphertext1
    assert ciphertext == new_ciphertext2

    return (
        CiphertextWithTag(ciphertext, tag),
        DecryptionContext(key1, nonce),
        DecryptionContext(key2, nonce),
    )


if __name__ == "__main__":
    try:
        check_auth()
    except Exception as e:
        print(e)
        exit(-1)

    ciphertextWithTag, context1, context2 = compute_gcm_collision()
    if verifyCollision_oracle(ciphertextWithTag, context1, context2) == True:
        print("Successfully computed a GCM collision!")
    else:
        print("Failed to compute a valid GCM collision.")
