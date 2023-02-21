"""
Operations in GF(2^128).
"""
import BitVector
from Crypto.Util.number import long_to_bytes, bytes_to_long

ZERO = long_to_bytes(0, 16)
ONE = long_to_bytes(1, 16)
TWO = long_to_bytes(2, 16)
THREE = long_to_bytes(3, 16)
FOUR = long_to_bytes(4, 16)
MINUS_ONE = ONE

GCM_MODULUS = BitVector.BitVector(
    # Corresponds to the polynomial x^128 + x^7 + x^2 + x + 1.
    bitlist=list([1] + [0] * 120 + [1, 0, 0, 0, 0, 1, 1, 1])
)
GCM_N = 128


def bytes_to_poly(a: bytes) -> BitVector.BitVector:
    bv = BitVector.BitVector(rawbytes=a)
    return bv


def poly_to_bytes(a: BitVector.BitVector) -> bytes:
    a_hex = a.get_bitvector_in_hex()
    a_bytes = bytes.fromhex(a_hex)
    # pad to 16 bytes
    a_bytes = bytes([0 for _ in range(16 - len(a_bytes))]) + a_bytes
    return a_bytes


def add(a: bytes, b: bytes) -> bytes:
    """
    Compute a + b in GF(2^128).
    """
    gf_a = bytes_to_poly(a)
    gf_b = bytes_to_poly(b)
    gf_result = gf_a ^ gf_b
    result_bytes = poly_to_bytes(gf_result)
    return result_bytes


def multiply(a: bytes, b: bytes) -> bytes:
    """
    Compute a * b in GF(2^128).
    """
    # Adapted from https://github.com/bozhu/AES-GCM-Python/blob/598b0379/aes_gcm.py#L30-L40
    # and Section 6.3 of https://doi.org/10.6028/NIST.SP.800-38D
    x = bytes_to_long(a)
    y = bytes_to_long(b)
    assert x < (1 << 128)
    assert y < (1 << 128)
    res = 0
    for i in range(127, -1, -1):
        res ^= x * ((y >> i) & 1)  # branchless
        x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
    assert res < 1 << 128
    return long_to_bytes(res, 16)


def square(a: bytes) -> bytes:
    """
    Compute a^2 in GF(2^128).
    """
    return multiply(a, a)


def pow(a: bytes, n: int) -> bytes:
    """
    Compute a^n in GF(2^128).
    """
    assert n >= 1
    output = a
    for _ in range(n - 1):
        output = multiply(output, a)
    return output


def inverse(a: bytes) -> bytes:
    """
    Compute a^(-1) in GF(2^128).
    """
    bv_a = BitVector.BitVector(intVal=bytes_to_long(a), size=128)
    le_a = BitVector.BitVector(bitstring=str(bv_a)[::-1])
    inverse = le_a.gf_MI(GCM_MODULUS, GCM_N)
    return long_to_bytes(int(BitVector.BitVector(bitstring=str(inverse)[::-1])), 16)


if __name__ == "__main__":
    a = bytes([i for i in range(16)])
    # conversion works
    assert a == poly_to_bytes(bytes_to_poly(a))
    # a + 0 = a
    assert add(a, ZERO) == a
    # a + 1 - 1 = a
    assert add(add(a, ONE), MINUS_ONE) == a
    # a * 0 = 0
    assert multiply(a, ZERO) == ZERO
    # a^2 = a * a
    assert pow(a, 2) == multiply(a, a)
    assert pow(a, 4) == multiply(square(a), square(a))

    print("all assertions pass")
