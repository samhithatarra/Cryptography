# Opaque implementation of Hybrid Encryption with Textbook RSA
import collections
import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

AEADCiphertext = collections.namedtuple("AEADCiphertext", ["ciphertext", "tag"])


class QQRSA(object):
    def __init__(self):
        self.__fixed_nonce = bytes([0 for _ in range(12)])  # fixed AES-GCM nonce
        self.__maxZnByteSize = 1024 // 8  # byte length plaintexts
        self.__rsaKey = RSA.generate(1024)  # use a 1024-bit RSA Key
        self.__message = (
            b"RSA{ffff}"  # "ffff" will be substituted with 2 random bytes in hex
        )

    def public_key(self) -> (int, int):
        pk = self.__rsaKey.public_key()
        return pk.n, pk.e

    def getWireData(self) -> (int, int, AEADCiphertext, bytes):
        # Key encapsulation mechanism (KEM) using textbook RSA encryption
        sessionKey = os.urandom(16)  # choose random 16-byte session key
        sessionKeyInt = int.from_bytes(sessionKey, "big")
        sessionKeyEncryptionInt = self.__rsaKey._encrypt(sessionKeyInt)
        sessionKeyEncryptionBytes = sessionKeyEncryptionInt.to_bytes(
            self.__maxZnByteSize, "big"
        )

        # Data encapsulation mechanism (DEM) using AES-GCM. Ok to use fixed nonce
        # since we choose new key each time we encrypt
        cipher = AES.new(sessionKey, mode=AES.MODE_GCM, nonce=self.__fixed_nonce)
        cipher.update(sessionKeyEncryptionBytes)
        ciphertext, tag = cipher.encrypt_and_digest(self.__message)
        flagEncryption = AEADCiphertext(ciphertext, tag)

        n, e = self.public_key()
        return n, e, flagEncryption, sessionKeyEncryptionBytes

    def checkConfirmation(
        self, flagEncryption: AEADCiphertext, sessionKeyEncryption: bytes
    ) -> bool:
        sessionKeyEncryptionInt = int.from_bytes(sessionKeyEncryption, "big")
        sessionKeyInt = pow(sessionKeyEncryptionInt, self.__rsaKey.d, self.__rsaKey.n)
        sessionKeyBytes = sessionKeyInt.to_bytes(self.__maxZnByteSize, "big")
        sessionKey = sessionKeyBytes[-16:]  # Just take low 16 bytes

        cipher = AES.new(sessionKey, mode=AES.MODE_GCM, nonce=self.__fixed_nonce)
        cipher.update(sessionKeyEncryption)
        try:
            message = cipher.decrypt_and_verify(
                flagEncryption.ciphertext, flagEncryption.tag
            )
        except ValueError:
            return False

        return True
