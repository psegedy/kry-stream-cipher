#!/usr/bin/env python3
import sys
from pathlib import Path


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

    def get_long_keystr(self, length):
        keystr = self.key
        keystr_list = [keystr.to_bytes(self.N_B, "little")]
        for i in range((length // self.N_B) - 1):
            keystr = self.step(keystr)
            keystr_list.append(keystr.to_bytes(self.N_B, "little"))

        return b"".join(keystr_list)

    def set_sub(self, key64):
        for x in range(self.N):
            self.SUB = [int(d) for d in format(x, "08b")]
            if key64 == self.get_long_keystr(64):
                print("Correct SUB = ", self.SUB)
                break

    def reverse_step(self, keystr):
        # Left most bit was created from index to SUB
        # 000, 011, 101, 111 => 0
        # 001, 010, 100, 110 => 1
        bit = ((0, 3, 5, 7), (1, 2, 4, 6))
        # do as many times as keystr_init was performed
        for _ in range(self.N // 2):
            # get the left most bit
            lm = (keystr >> self.N - 1) & 1
            unsures = list(bit[lm])

            for i in range(2, self.N + 1):
                cur_lm = (keystr >> self.N - i) & 1
                if cur_lm == 0:
                    for j in range(4):
                        if unsures[j] & 0b011:
                            unsures[j] = (unsures[j] << 1) + 1
                        else:
                            unsures[j] = (unsures[j] << 1) + 0
                else:
                    for j in range(4):
                        if unsures[j] & 0b011:
                            unsures[j] = (unsures[j] << 1) + 0
                        else:
                            unsures[j] = (unsures[j] << 1) + 1

            unsures = [(unsure >> 1) & ~(1 << self.N) for unsure in unsures]

            for unsure in unsures:
                if self.step(unsure) == keystr:
                    keystr = unsure

        return keystr


class Decrypt:
    def __init__(self, dirpath, keystream=None):
        self.keystream = None
        self.dirpath = Path(dirpath)
        self.open_text_path = self.dirpath.joinpath("bis.txt").resolve()
        self.cipher_text_path = self.dirpath.joinpath("bis.txt.enc").resolve()
        self.hint_path = self.dirpath.joinpath("hint.gif.enc").resolve()
        self.cipher_path = self.dirpath.joinpath("super_cipher.py.enc").resolve()
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

    def get_algorithm_chunk(self):
        data = self.cipher_path.read_bytes()[: len(self.keystream)]
        return self._bxor(data, self.keystream)

    def decrypt(self, filepath, outfile):
        data = filepath.read_bytes()
        cipher = SuperCipher(self.keystream[:32])
        # set sub due to error in assignment
        # cipher.set_sub(self.keystream[:64])
        keystr = cipher.get_long_keystr(len(data))
        decrypted = self._bxor(data, keystr)
        with open(outfile, "wb") as f:
            f.write(decrypted)

    def get_secret(self):
        cipher = SuperCipher(self.keystream[:32])
        res = cipher.reverse_step(cipher.key)
        return res


def main():
    if len(sys.argv) != 2:
        print("Usage: solution.py <dirpath>")

    decrypt = Decrypt(sys.argv[1])
    # decrypt.get_algorithm_chunk()
    # decrypt.decrypt(decrypt.hint_path, 'hint.gif')
    # decrypt.decrypt(decrypt.cipher_path, 'super_cipher.py')
    secret = decrypt.get_secret().to_bytes(32, "little").strip(b"\x00")
    print(secret.decode("utf-8"))


if __name__ == "__main__":
    main()
