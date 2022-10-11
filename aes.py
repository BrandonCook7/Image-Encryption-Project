import pandas as pd
import numpy as np
import math
class AES():
    def __init__(self, key_phrase):
        #Todo: Add a way to pad the key
        #Key must be exactly 128 bits or exactly 16 chars currently
        self.key_phrase = key_phrase
        self.block_size = 128
        self.rounds = 10

    def encrypt_aes(key):
        s = pd.Series([1,2])
        print(s)
        return
    def convert_key(self):
        #Example passphrase "password12345678"
        if len(self.key_phrase) * 8 < self.block_size:
            print(len(self.key_phrase))
            #Todo: Pad Key
            print("Pad Key")
        elif len(self.key_phrase) * 8 > self.block_size:
            raise ValueError("Key too large for block size")
        else:
            #format(ord("c"), "x")
            hex_list = [format(ord(c), "x") for c in list(self.key_phrase) if True]
            m = np.array(hex_list).reshape(4,4).swapaxes(0,1)
            print(m)
    #Uses PKCS#7 Padding
    def pad_hex(self):
        #Once hex value here is 8 bits/1 byte
        hex_list = [format(ord(c), "x") for c in list(self.key_phrase) if True]
        blocks = 1
        bits_left = 0
        bits_total = len(hex_list) * 8
        if bits_total > self.block_size:
            overflow = bits_total - self.block_size
            blocks = overflow / self.block_size
            #Round up blocks if not an even value
            blocks = math.ceil(blocks)
            bits_left = bits_total % 128

        else:
            bits_left = self.block_size - len(hex_list) * 8#128 - 96
        print(blocks)
        bytes_left: int = int(bits_left / 8)
        print(bytes_left)
        #For the PKCS#7 Padding you add the bytes left as a hex value to all the empty spaces
        hex_to_append = hex(bytes_left)
        print("BEFORE PADDING: \n", hex_list)
        for i in range(bytes_left):
            hex_list.append(hex_to_append)
        print("AFTER PADDING: \n", hex_list)
