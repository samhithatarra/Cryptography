from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from hw1_AESCtr import AESCtr
import pytest

msg = [b"Hellow world my name is samhitha"]  # More test cases at grading


@pytest.mark.parametrize("data", msg)
def test_encryption(data):
    key = get_random_bytes(16)

    try:
        cipher = AESCtr(key)
        nonce, ct = cipher.encrypt(data)

        lib_cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        pt = lib_cipher.decrypt(ct)
        assert data == pt, "The ciphertext is not correct."
    except Exception as e:
        assert False, f"Exception raised {e}"


@pytest.mark.parametrize("data", msg)
def test_decryption(data):
    key = get_random_bytes(16)

    try:
        lib_cipher = AES.new(key, AES.MODE_CTR)
        nonce = lib_cipher.nonce
        ct = lib_cipher.encrypt(data)

        cipher = AESCtr(key)
        pt = cipher.decrypt(nonce, ct)
        assert data == pt, "The decrypted text is not the same as the original text"
    except Exception as e:
        assert False, f"Exception raised {e}"
