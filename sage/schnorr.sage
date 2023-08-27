from sage.all import *
from random import randint
from hashlib import sha256

# Using secp256r1
# https://neuromancer.sk/std/secg/secp256r1
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
F = GF(p)
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
E = EllipticCurve(F, [a, b])

G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

def generate_secret_key():
    return randint(1, n-1)

def generate_public_key(sk):
    return sk * G

def hash(message: str) -> int:
    hasher = sha256()
    hasher.update(bytes(message, "ascii"))
    e_bytes = hasher.digest()
    long_int = int.from_bytes(e_bytes)
    return long_int
    
    # Generate hash of the message, public key and another curve point
def challenge(message, public_key, R) -> int:
    combination = message + str(public_key) + str(R)
    return hash(combination)

def sign(message, secret_key): 
    public = generate_public_key(secret_key)
    k = randint(1, n-1)
    R = k * G
    e = challenge(message, public, R)
    s = k + secret_key * e
    return (s, R)

def verify(s, message, public_key, R):
    e = challenge(message, public_key, R)  
    r_v = R + public_key * e
    # s*G = (k + Sk * e)G = kG + SkG*e = R + Pk*e
    # verifier returns true if the hash used to create the signature equals the one used to verify
    verifier = s * G == r_v
    return verifier

def get_random():
    r = randint(1, n-1)
    R = G * r
    return R

def signer(secret_key):
    public_key = generate_public_key(secret_key)
    r = get_random()
    return(public_key, r)

def signer_round_1(public_key, public_key_list):
    a = hash(str(public_key_list + public_key))
    public_key_aggregate = 0
    for public_key in public_key_list:
        public_key_aggregate += public_key
    return (a, public_key_aggregate)

def signer_round_2(R_list, commitment_list):
    hash_list: list
    for R in R_list:
        hash_list.append(hash(str(R)))
    return hash_list == commitment_list

def signer_round_3(secret_key, r, R_list, public_key_aggregate, message):
    R_aggregate = 1
    for R in R_list:
        R_aggregate += R
    c = hash(str(public_key_aggregate) + str(R_aggregate) + message)
    s = r + secret_key * c

def multi_sign(message, public_keys):
    public_sum = 0
    for public_key in public_keys:
        public_sum += public_key

def multi_verify(message, public_key_list, signature, R):
    a: int
    a_list: list
    public_key_aggregate = 0
    for public_key in public_key_list:
        a = hash(str(public_key) + str(public_key_list))
        a_list.append(a)
        public_key_aggregate += public_key 
    c = hash(str(public_key_aggregate) + str(R) + message)
    verifier = signature * G == R + public_key_aggregate * c
    return verifier
    
    







