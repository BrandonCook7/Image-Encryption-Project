from re import I
import pandas as pd
import numpy as np
import math

import utils

from pyparsing import col
from sqlalchemy import column

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

#rcon_lookup = (0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)
rcon_lookup = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

#https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
mix_columns_matrix = np.array([[0x02, 0x03, 0x01, 0x01],
                              [0x01, 0x02, 0x03, 0x01],
                              [0x01, 0x01, 0x02, 0x03],
                              [0x03, 0x01, 0x01, 0x02]])

class AES():
    def __init__(self, key_phrase, message):
        #Key must be exactly 128 bits or exactly 16 chars currently
        self.key_phrase = key_phrase
        self.message = message
        self.block_size = 128
        self.rounds = 10
        self.n = 4 #4 for 128bits, 6 for 192bits, 8 for 256bits

    def sub_from_s_box(self, _hex):
        if _hex[1] == 'x':
            if len(_hex) == 3:
                x_axis = '0'
                y_axis = _hex[2]
            else:
                x_axis = _hex[2]
                y_axis = _hex[3]
        else:
            x_axis = _hex[0]
            y_axis = _hex[1]
        #Converts hexadecimal values to integers
        x_coord = int(x_axis, 16)
        y_coord = int(y_axis, 16)
        row = x_coord * 16
        #Don't use hex function since it will print 0x7 instead of 0x07
        #return (f"0x{(s_box[row + y_coord]):02x}")
        return hex(s_box[row+y_coord])

    def create_rcon_table(self):
        #Create 4x11 array in numpy
        #Create 4x11 RCOn table in numpy
        rcon_table = np.empty(shape=(4, 10), dtype=object)
        #rcon_table = np.zeros((4, 11), dtype=str)
        for i in range(10):
            for j in range(4):
                if j == 0:
                    rcon_table[0][i] = hex(rcon_lookup[i])#f"0x{(rcon_lookup[i]):02x}"
                else:
                    rcon_table[j][i] = hex(0)
        return rcon_table

    #The key scheduler happens here
    def create_round_keys(self, key_array: np.ndarray):
        #This array will holds the cipher keys and all round keys

        #Notes: Using default Python list as nesting a 2d array into a 1d numpy array, because it merges the columns
        key_expanded = [key_array] #np.array(key_array)
        #Creates rot word as 1d array
        # column_array = self.rotate_column_up(key_array, 3)
        # print(column_array)

        #Substitute Bytes
        # for index in np.ndindex(column_array.shape):
        #     column_array[index] = self.sub_from_s_box(column_array[index])[2:]#Trim to ignore 0x
        #Create round constants table
        rcon_table = self.create_rcon_table()

        for round in range(self.rounds):
            round_key_x = np.empty(shape=(4,4), dtype='<U4', order='C')
            for col in range(4):
                if col == 0:
                    #Creates rot word as 1d array
                    rot_word = self.rotate_column_up(key_expanded[round], 3)
                    #Substitute Bytes
                    for index in np.ndindex(rot_word.shape):
                        rot_word[index] = self.sub_from_s_box(rot_word[index])#[2:]#Trim to ignore 0x
                    #Convert's hex string values to integers for XOR operation
                    print(int(rcon_table[0][round],16))
                    print(rcon_table[0][round])
                    val1_int = int(key_expanded[round][0][col],16) ^ int(rot_word[0],16) ^ int(rcon_table[0][round],16)
                    val2_int = int(key_expanded[round][1][col],16) ^ int(rot_word[1],16) ^ int(rcon_table[1][round],16)
                    val3_int = int(key_expanded[round][2][col],16) ^ int(rot_word[2],16) ^ int(rcon_table[2][round],16)
                    val4_int = int(key_expanded[round][3][col],16) ^ int(rot_word[3],16) ^ int(rcon_table[3][round],16)
                    #After XOR operation stores keys back in hex values
                    # round_key_x[col][0] = hex(val1_int)
                    # round_key_x[col][1] = hex(val2_int)
                    # round_key_x[col][2] = hex(val3_int)
                    # round_key_x[col][3] = hex(val4_int)
                    round_key_x[0][col] = hex(val1_int)
                    round_key_x[1][col] = hex(val2_int)
                    round_key_x[2][col] = hex(val3_int)
                    round_key_x[3][col] = hex(val4_int)
                else:
                    # val1_int = int(key_expanded[round][0][col],16) ^ int(round_key_x[col-1][0],16)
                    # val2_int = int(key_expanded[round][1][col],16) ^ int(round_key_x[col-1][1],16)
                    # val3_int = int(key_expanded[round][2][col],16) ^ int(round_key_x[col-1][2],16)
                    # val4_int = int(key_expanded[round][3][col],16) ^ int(round_key_x[col-1][3],16)
                    val1_int = int(key_expanded[round][0][col],16) ^ int(round_key_x[0][col-1],16)
                    val2_int = int(key_expanded[round][1][col],16) ^ int(round_key_x[1][col-1],16)
                    val3_int = int(key_expanded[round][2][col],16) ^ int(round_key_x[2][col-1],16)
                    val4_int = int(key_expanded[round][3][col],16) ^ int(round_key_x[3][col-1],16)
                    # round_key_x[col][0] = hex(val1_int)
                    # round_key_x[col][1] = hex(val2_int)
                    # round_key_x[col][2] = hex(val3_int)
                    # round_key_x[col][3] = hex(val4_int)
                    round_key_x[0][col] = hex(val1_int)
                    round_key_x[1][col] = hex(val2_int)
                    round_key_x[2][col] = hex(val3_int)
                    round_key_x[3][col] = hex(val4_int)
            #Add new round key to list
            key_expanded.append(round_key_x)
            #print(round_key_x)
        #print(len(key_expanded))
        return key_expanded
    
    #Rotate a specific column up one from a 4x4 ndarray, uses for the RotWord
    def rotate_column_up(self, key_array: np.ndarray, column):
        column_array = np.array([key_array[1][column], key_array[2][column], key_array[3][column], key_array[0][column]])
        return column_array
        # temp = key_array[0][column]
        # key_array[0][column] = key_array[1][column]
        # key_array[1][column] = key_array[2][column]
        # key_array[2][column] = key_array[3][column]
        # key_array[3][column] = temp
        # print(column_array)

    def mix_columns(self, mix_array: np.ndarray):
        #(𝚍𝟺×𝟶𝟸)+(𝚋𝚏×𝟶𝟹)+(𝟻𝚍×𝟶𝟷)+(𝟹𝟶×𝟶𝟷)
        for i in range(4):
            input_array = np.array([mix_array[0][i], mix_array[1][i], mix_array[2][i], mix_array[3][i]])
            output = self.mix_column(input_array)
            mix_array[0][i] = output[0]
            mix_array[1][i] = output[1]
            mix_array[2][i] = output[2]
            mix_array[3][i] = output[3]
        


    def mix_column(self, column):
        mixed_column = np.empty(shape=4, dtype='<U4')
        #loop through matrix
        for row in range(4):
            temp_store = []
            for col in range(4):
                if mix_columns_matrix[row][col] == 1:
                    mul_val = int(column[col],16)
                elif mix_columns_matrix[row][col] == 2:
                    mul_val = utils.multiply_by_2(int(column[col],16))
                elif mix_columns_matrix[row][col] == 3:
                    mul_val = utils.multiply_by_3(int(column[col],16))
                else:
                    raise RuntimeError("Could not find correct matrix value")
                temp_store.append(mul_val)
            #After loop XOR all values together
            total = temp_store[0] ^ temp_store[1] ^ temp_store[2] ^ temp_store[3]
            mixed_column[row] = (hex(total))
        return mixed_column

    def sub_bytes(self, sub_array: np.ndarray):
        for pos, x in np.ndenumerate(sub_array):
            sub_array[pos[0]][pos[1]] = self.sub_from_s_box(x)
    #This function supports all AES bit configurations
    def shift_rows(self, shift_array: np.ndarray):
        shift_array[1] = np.roll(shift_array[1], -1)
        shift_array[2] = np.roll(shift_array[2], -2)
        shift_array[3] = np.roll(shift_array[3], -3)

    def add_round_key(self, array, round_key):
        return_array = np.empty(shape=(4,4), dtype='<U4')
        for i in range(4):
            for j in range(4):
                return_array[i][j] = hex(int(array[i][j],16) ^ int(round_key[i][j], 16))
        return return_array
    
    def encrypt_aes(self):
        #TODO Implement CBC option
        key = self.convert_key()
        round_keys = self.create_round_keys(key)
        if len(round_keys) != self.rounds + 1:
            return ValueError("Wrong amount of round keys")
        message_blocks = self.convert_message()
        print("ORIGINAL BLOCKS")
        print(message_blocks)
        for b_index in range(len(message_blocks)):
            #First round
            message_blocks[b_index] = self.add_round_key(message_blocks[b_index], round_keys[0])
            #Rounds 2-10
            for round in range(self.rounds - 1):
                # print(block)
                self.sub_bytes(message_blocks[b_index])
                # print(block)
                self.shift_rows(message_blocks[b_index])
                # print("SHIFT ROWS \n")
                # print(block)
                # print("NEW BLOCK \n")
                self.mix_columns(message_blocks[b_index])
                # print("MIX COLUMNS \n")
                # print(block)
                message_blocks[b_index] = self.add_round_key(message_blocks[b_index], round_keys[round+1])
                # print("ADD ROUND KEY \n")
                # print(block)
            #Round 11
            self.sub_bytes(message_blocks[b_index])
            self.shift_rows(message_blocks[b_index])
            message_blocks[b_index] = self.add_round_key(message_blocks[b_index], round_keys[10])
        print("ENCRYPTED BLOCKS")
        print(message_blocks)
        self.convert_blocks_to_output(message_blocks)
        self.convert_input_to_blocks()

    def decyrpt_aes(self):
        key = self.convert_key()
        round_keys = self.create_round_keys(key)
        if len(round_keys) != self.rounds + 1:
            return ValueError("Wrong amount of round keys")

    def convert_input_to_blocks(self):
        encrypted_blocks = []
        file = open("input.txt", "r")
        lines = file.readlines()
        file.close()
        blocks_string = lines[0]
        print(lines)
        blocks_total = len(blocks_string) / 32
        blocks_total = int(blocks_total)
        
        k = 0 #Used for slicing the block string
        for block in range(blocks_total):
            block_state = np.empty(shape=(4, 4), dtype='<U4')

            for i in range(4):
                for j in range(4):
                    block_state[j][i] = hex(int(blocks_string[k:k+2],16))
                    k += 2
            encrypted_blocks.append(block_state)    
        print(encrypted_blocks)
        #print(hex(int(blocks_string[0:2], 16)))

    def convert_blocks_to_output(self, message_blocks: list):
        file = open("output.txt", "w")
        for block in message_blocks:
            temp_str = ""
            for i in range(4):
                for j in range(4):
                    temp_str += (f"0x{(int(block[j][i],16)):02x}")[2:]#block[j][i]#str(int(block[j][i],16))
            file.write(temp_str)
        file.close()

    #Similar to convert key but is not limited by block size
    def convert_message(self):
        message_blocks = []#np.empty()
        hex_list = [hex(ord(c)) for c in list(self.message) if True]
        if len(self.message) * 8 < self.block_size:
            self.pad_hex(hex_list)
            message_blocks.append(np.array(hex_list).reshape(4,4).swapaxes(0,1))
        elif len(self.message) * 8 >= self.block_size:
            #Pads the message if it is not in 128 bit multiples
            if (len(self.message) * 8) % self.block_size == 0:
                print("FITS PERFECTLY NO PADDING")
                blocks_total = int((len(self.message) * 8) / self.block_size)
                for i in range(blocks_total):
                    block = hex_list[i*16:(i+1)*16]
                    message_blocks.append(np.array(block).reshape(4,4).swapaxes(0,1))
            else:
                filled_blocks_total = math.floor((len(self.message) * 8) / self.block_size)
                #Filled all full blocks
                for i in range(filled_blocks_total):
                    block = hex_list[i*16:(i+1)*16]
                    message_blocks.append(np.array(block).reshape(4,4).swapaxes(0,1))
                tail_block = hex_list[(i+1)*16:]
                self.pad_hex(tail_block)
                message_blocks.append(np.array(tail_block).reshape(4,4).swapaxes(0,1))
                print("MUST PAD last block")
        
        return message_blocks

    def convert_key(self):
        #Example passphrase "password12345678"
        #hex_list = [format(ord(c), "x") for c in list(self.key_phrase) if True]

        hex_list = [hex(ord(c)) for c in list(self.key_phrase) if True]
        if len(self.key_phrase) * 8 < self.block_size:
            #print(len(self.key_phrase))
            self.pad_hex(hex_list)
        elif len(self.key_phrase) * 8 > self.block_size:
            raise ValueError("Key too large for block size")

        key_array = np.array(hex_list).reshape(4,4).swapaxes(0,1)
        return key_array
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
        #print(blocks)
        bytes_left: int = int(bits_left / 8)
        #print(bytes_left)
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


