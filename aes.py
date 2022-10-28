import pandas as pd
import numpy as np
import math

from pyparsing import col

#https://en.wikipedia.org/wiki/Rijndael_S-box
s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)


class AES():
    def __init__(self, key_phrase):
        #Todo: Add a way to pad the key
        #Key must be exactly 128 bits or exactly 16 chars currently
        self.key_phrase = key_phrase
        self.block_size = 128
        self.rounds = 10

    def sub_from_s_box(self, _hex):
        if _hex[1] == 'x':
            x_axis = _hex[0]
            y_axis = _hex[2]
        else:
            x_axis = _hex[0]
            y_axis = _hex[1]
        #Converts hexadecimal values to integers
        x_coord = int(x_axis, 16)
        y_coord = int(y_axis, 16)
        #print(hex(s_box[1]))
        row = x_coord * 16
        return hex(s_box[row + y_coord])

    #The key scheduler happens here
    def key_expansion(self, key_array: np.ndarray):
        key_copy = key_array.copy()
        self.rotate_column_up(key_copy, 3)
        print(key_copy)
        _loc = key_copy[2][3]
        print("Key: " + _loc + " To S-Box: " + self.sub_from_s_box(_loc))


    
    #Rotate a specific column up one from a 4x4 ndarray, uses for the RotWord
    def rotate_column_up(self, key_array: np.ndarray, column):
        temp = key_array[0][column]
        key_array[0][column] = key_array[1][column]
        key_array[1][column] = key_array[2][column]
        key_array[2][column] = key_array[3][column]
        key_array[3][column] = temp


    def encrypt_aes(self):
        #s = pd.Series([1,2])
        # hex_list = [format(ord(c), "x") for c in list(self.key_phrase) if True]
        # print("BEFORE PADDING: \n", hex_list)
        # self.pad_hex(hex_list)
        # print("AFTER PADDING: \n", hex_list)
        # self.unpad_hex(hex_list)
        # print("REMOVED PADDING: \n", hex_list)
        return
    def convert_key(self):
        #Example passphrase "password12345678"
        hex_list = [format(ord(c), "x") for c in list(self.key_phrase) if True]
        if len(self.key_phrase) * 8 < self.block_size:
            print(len(self.key_phrase))
            self.pad_hex(hex_list)
        elif len(self.key_phrase) * 8 > self.block_size:
            raise ValueError("Key too large for block size")

        key_array = np.array(hex_list).reshape(4,4).swapaxes(0,1)
        #print(key_array)
        self.key_expansion(key_array)
    #Uses PKCS#7 Padding, modifies hex_list by reference
    def pad_hex(self, hex_list: list):
        #Once hex value here is 8 bits/1 byte
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
        for i in range(bytes_left):
            hex_list.append(hex_to_append)
    #Undoes PKCS#7 padding, modifies hex_list by reference
    def unpad_hex(self, hex_list: list):
        hex_len = hex_list[len(hex_list)-1]
        padding_len = int(hex_len, 16)
        rev_list = hex_list.copy()
        rev_list.reverse()
        #Check to see if hex list is padded
        is_padded = True
        for i in range(1, padding_len):
            if rev_list[i] != rev_list[i-1]:
                is_padded = False
                break
        if is_padded:
            for i in range(padding_len):
                hex_list.pop()


