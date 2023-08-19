from sage.all import *
from random import randint
from hashlib import sha256
from math import log2

# Using secp256r1
# https://neuromancer.sk/std/secg/secp256r1
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
F = GF(p)
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
E = EllipticCurve(F, [a, b])

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 # The number of points on E

assert(E.order() == n)

# Chosen generator
G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

# Identity TODO: Still a hack
O = E(0, 1, 0)

def generate_secret_key():
    return randint(1, n-1)

def generate_public_key(sk):
    return sk * G

def hash(message: str) -> int:
    hasher = sha256()
    hasher.update(bytes(message, "ascii"))
    e_bytes = hasher.digest()
    long_int = int.from_bytes(e_bytes)
    l_n = int(log2(n))
    shift_length = 256 - l_n

    return long_int >> shift_length

def sign(message: str, secret_key):
    # 1. Calculate e = hash(m)
    # 2. let z = l_n left most bits
    z = hash(message)

    r = 0
    s = 0
    while (r == 0) or (s ==0): 
        # 3. Choose a secure random integer k
        k = randint(1, n-1)

        # 4. Calculate k * G and use the x coordinate
        # 5. Calculate r = x mod n
        r = (k * G)[0] % n
        
        # 6. Calculate s = k^{-1} (z + r * sk) mod n
        s = pow(k, -1, n) * (z + r * secret_key) % n

    return r, s

def verify(message: str, signature: tuple[int, int], public_key) -> bool:
    # Preliminary checks
    assert(public_key != O)
    assert(E.is_on_curve(public_key[0], public_key[1]))
    
    (r, s) = signature
    # 1. 1 < r,s < n-1
    check_rs_range = 1 < r and r < n-1 and 1 < s and s < n-1

    # 2. Calculate e = hash(m)
    # 3. z = l_n left most bits of e
    z = hash(message)

    # 4. Calculate u1 = z * s^{-1} mod n and u2 = r * s^{-1} mod n
    u_1 = z * pow(s, -1, n) % n
    u_2 = r * pow(s, -1, n) % n

    # 5. Calculate u_1 * G + u_2 * public_key
    x = (u_1 * G + u_2 * public_key)[0]

    # 6. r == x mod n
    check_r_x_coord = (r % n) == (x % n)

    return check_rs_range and check_r_x_coord

# TODO: Add tests
