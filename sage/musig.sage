from sage.all import *
from random import randint
import random
from hashlib import sha256
from enum import Enum

random.seed(int(12345))

# Using secp256r1
# https://neuromancer.sk/std/secg/secp256r1
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
F = GF(p)
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
E = EllipticCurve(F, [a, b])

G = E(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

O = E(0, 1, 0)

n: int = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

class DomainSep(Enum):
    COM = "com"
    AGG = "agg"
    SIG = "sig"

def hash_agg(pk_list, pk) -> int:
      hasher = sha256()
      hasher.update(DomainSep.AGG.value.encode("ascii"))
      for pk_i in pk_list:
            hasher.update(str(pk_i).encode("ascii"))
      hasher.update(str(pk).encode("ascii"))

      return int.from_bytes(hasher.digest())

def hash_comm(group_elem) -> int:
      hasher = sha256()
      hasher.update(DomainSep.COM.value.encode("ascii"))
      hasher.update(str(group_elem).encode("ascii"))

      return int.from_bytes(hasher.digest())

def hash_sig(group_elem_X, group_elem_R, message: str) -> int:
      hasher = sha256()
      hasher.update(DomainSep.SIG.value.encode('ascii'))
      hasher.update(str(group_elem_X).encode('ascii'))
      hasher.update(str(group_elem_R).encode('ascii'))
      hasher.update(message.encode('ascii'))

      return int.from_bytes(hasher.digest())

class Signer():
      def __init__(self) -> None:
            self._sk: int = randint(1, n-1)
            self.pk = self._sk * G
      
      def calculate_a(self, all: list['Signer']):
            self.pk_list = list(map(lambda x: x.pk, all))
            self.list_a = list()            
            for signer in all:
                  self.list_a.append(hash_agg(self.pk_list, signer.pk))
            
            self.a = hash_agg(self.pk_list, self.pk)

      # pk list is saved as an attribute of self in calculate_a to avoid calculating it again for calculate_x
      def calculate_x(self):
            self.x = reduce(lambda x, y: x + y, map(lambda pairs: pairs[0] * pairs[1], zip(self.list_a, self.pk_list)))

            return self.x

      def commit(self):
            self._r = randint(0, p-1)
            self.R = self._r * G
            self.t = hash_comm(self.R)

            return self.t
      
      def open_commit(self):
            return self.R
      
      def verify_one_commit(self, t, R):
            return t == hash_comm(R)
      
      def verify_all_commits(self, ts: list[int], Rs):
            assert len(ts) == len(Rs)
            # assert(len(ts) == len(Rs))
            verified = True
            for (t, R) in zip(ts, Rs):
                  verified &= self.verify_one_commit(t, R)
            
            return verified
      
      def calculate_s(self, c: int):
            return (self._r + c * self.a * self._sk) % n

class MultiSig():
      def __init__(self, signers: list[Signer], message) -> None:
            self.signers = signers

            self._message = message

            self.pk_list = [signer.pk for signer in self.signers]

      def round_1(self):
            for signer in self.signers:
                  signer.calculate_a(self.signers)
                  self.x = signer.calculate_x()
      
      def round_2(self):
            self.list_comm = list()
            for signer in self.signers:
                  self.list_comm.append(signer.commit())

            self.list_openings = list()
            for signer in self.signers:
                  self.list_openings.append(signer.open_commit())

            self.all_verified = True 
            for signer in self.signers:
                  self.all_verified &= signer.verify_all_commits(self.list_comm, self.list_openings)
            assert self.all_verified == True

      def round_3(self):
            self.R = O
            for signer in self.signers:
                  self.R += signer.R

            self.c = hash_sig(self.x, self.R, self._message) #type: ignore

            self.list_s = list()

            for signer in self.signers:
                  self.list_s.append(signer.calculate_s(self.c))
            
            self.s = 0

            for s in self.list_s:
                  self.s += s
            
            # this is n, order of the elliptic curve group, NOT p, modulus of the finite field
            self.s %= n
            
      def sign(self):
            self.round_1()
            self.round_2()
            self.round_3()
            return (self.R, self.s)

def verify(sig, pk_list, message):
      (R, s) = sig
      assert s < n
      assert R != O
      list_a = list()
      for pk in pk_list:
            list_a.append(hash_agg(pk_list, pk))
      
      X = O
      for (a, pk) in zip(list_a, pk_list):
            X += a * pk
      
      c = hash_sig(X, R, message)

      return (s * G == R + c * X)

s1 = Signer()
s2 = Signer()
s3 = Signer()

msig = MultiSig([s1, s2, s3], "Hi")