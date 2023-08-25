from sage.all import *
from random import randint

# A and B both agree on a elliptic curve E, and a particular generator G of the group
# Goal: A and B to arrive at a shared secret.
# A and B have secret keys sk_A and sk_B these are numbers [0, 2 ** 256]
# Derive their public keys by calculating pk_A = sk_A * G, pk_B = sk_B * G. <- G + G + G .... sk_B times.
# A and B share their public keys, and the corresponding shared secret will be
# S = sk_A * pk_B (computed by A). S = sk_B * pk_A (computed B) 
# S = (sk_A * sk_B) * G

# Choose a particular field, a common choice is the curve `Curve25519`
p = 2 ** 255 - 19
F = GF(p)
# Curve is defined using the parameters
# y^2 = x^3 + 486662 x^2 + x
E = EllipticCurve(F, [0, 486662, 0, 1, 0])
# Particular generator A and B agree on is of the form (9 : ______ : 1)
G = E.lift_x(9)
E_ord = E.order()

def generate_secret_key():
    return randint(0, E_ord)

def generate_public_key(secret_key):
    return secret_key * G

def generate_secret(secret_key, public_key):
    return secret_key * public_key

