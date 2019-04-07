#!/usr/bin/env python3
import sys
from collections import deque
from pathlib import Path

from satispy import Variable
from satispy.cnf import Cnf
from satispy.solver import Minisat


class SuperCipher:
    # obtained from super_cipher.py.enc

    def __init__(self, key):
        # self.SUB = [0, 1, 1, 0, 0, 1, 0, 1]
        self.SUB = [0, 1, 1, 0, 1, 0, 1, 0]
        self.N_B = 32
        self.N = 8 * self.N_B
        self.key = int.from_bytes(key, "little")

    def step(self, x):
        x = (x & 1) << self.N + 1 | x << 1 | x >> self.N - 1
        y = 0
        for i in range(self.N):
            y |= self.SUB[(x >> i) & 7] << i
        return y

    def keystr_init(self):
        for i in range(self.N // 2):
            self.key = self.step(self.key)


class Decrypt:
    def __init__(self, dirpath, keystream=None):
        self.dirpath = Path(dirpath)
        self.open_text_path = self.dirpath.joinpath("bis.txt").resolve()
        self.cipher_text_path = self.dirpath.joinpath("bis.txt.enc").resolve()
        self.keystream = keystream or self._get_keystream()

    @staticmethod
    def _bxor(bytes1, bytes2):
        """XOR two files, byte by byte. Returns bytes object"""
        # zip bytes from both files, apply XOR
        return b"".join([bytes([b1 ^ b2]) for b1, b2 in zip(bytes1, bytes2)])

    def _get_keystream(self):
        open_text = self.open_text_path.read_bytes()
        cipher_text = self.cipher_text_path.read_bytes()
        return self._bxor(open_text, cipher_text)

    @staticmethod
    def _reverse_step_sat(cipher):
        solver = Minisat()
        var = [Variable(str(x)) for x in range(cipher.N)]

        def _cnf_bit(bit, c, b, a):
            cnf = (a | b | c) & (-b | -c) & (-a | -c)
            return cnf if bit else -cnf

        def _vars(i):
            return [var[i], var[(i + 1) % cipher.N], var[(i + 2) % cipher.N]]

        for _ in range(cipher.N // 2):
            exp = Cnf()
            for i in range(cipher.N):
                exp &= _cnf_bit((cipher.key >> i) & 1, *_vars(i))

            result = solver.solve(exp)
            bits = deque([int(result[v]) for v in var])
            bits.reverse()
            bits.rotate(-1)
            out = 0
            for bit in bits:
                out = (out << 1) | bit

            cipher.key = out
        return cipher.key

    def get_secret(self):
        cipher = SuperCipher(self.keystream[:32])
        res = self._reverse_step_sat(cipher)
        return res


def main():
    if len(sys.argv) != 2:
        print("Usage: solution_sat.py <dirpath>")

    decrypt = Decrypt(sys.argv[1])
    secret = decrypt.get_secret().to_bytes(32, "little").strip(b"\x00")
    print(secret.decode("utf-8"))


if __name__ == "__main__":
    main()
