from re import I
import pandas as pd
import numpy as np
import math

import os
import utils
import base64

from tqdm import tqdm

import time

#rcon_lookup = (0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)
rcon_lookup = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)

#https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
mix_columns_matrix = np.array([[0x02, 0x03, 0x01, 0x01],
                              [0x01, 0x02, 0x03, 0x01],
                              [0x01, 0x01, 0x02, 0x03],
                              [0x03, 0x01, 0x01, 0x02]])

inv_mix_columns_matrix = np.array([[0x0e, 0x0b, 0x0d, 0x09],
                                [0x09, 0x0e, 0x0b, 0x0d],
                                [0x0d, 0x09, 0x0e, 0x0b],
                                [0x0b, 0x0d, 0x09, 0x0e]])

class AES():
    def __init__(self):
        #Key must be exactly 128 bits or exactly 16 chars currently
        self.key_phrase = ""
        self.message = ""
        self.block_size = 128
        self.rounds = 10
        self.n = 4 #4 for 128bits, 6 for 192bits, 8 for 256bits
    def create_inverse_s_box_dict(self):
        table_dict = {}
        for y_coord in range(16):
            for x_coord in range(16):
                row = y_coord * 16
                table_dict[hex(utils.s_box[row+x_coord])] = (hex(x_coord), hex(y_coord))
        return table_dict
                

    def inverse_sub_from_s_box(self, _hex):
        for y_coord in range(16):
            for x_coord in range(16):
                row = y_coord * 16
                if hex(utils.s_box[row+x_coord]) == _hex:
                    x_hex = hex(x_coord)
                    y_hex = hex(y_coord)
                    return hex(int(y_hex[2] + x_hex[2],16))
        return LookupError("Can not find inverse of that hexadecimal")

    def read_txt_file(self, filename):
        file = open(filename, "r")
        lines = file.readlines()
        file.close()
        for i in lines:
            self.message += i

    def create_rcon_table(self):
        #Create 4x11 array in numpy
        #Create 4x11 RCOn table in numpy
        rcon_table = np.empty(shape=(4, 10), dtype=object)
        #rcon_table = np.zeros((4, 11), dtype=str)
        for i in range(10):
            for j in range(4):
                if j == 0:
                    rcon_table[0][i] = rcon_lookup[i]#f"0x{(rcon_lookup[i]):02x}"
                else:
                    rcon_table[j][i] = 0
        return rcon_table

    #The key scheduler happens here
    def create_round_keys(self, key_array: np.ndarray):
        #This array will holds the cipher keys and all round keys

        #Notes: Using default Python list as nesting a 2d array into a 1d numpy array, because it merges the columns
        key_expanded = [key_array] #np.array(key_array)
        rcon_table = self.create_rcon_table()

        for round in range(self.rounds):
            round_key_x = np.empty(shape=(4,4), dtype='i', order='C')
            for col in range(4):
                if col == 0:
                    #Creates rot word as 1d array
                    rot_word = self.rotate_column_up(key_expanded[round], 3)
                    #Substitute Bytes
                    for index in np.ndindex(rot_word.shape):
                        #Must pass as a hex because lookup_table splices the hex to find it's value
                        rot_word[index] = utils.lookup_table(hex(rot_word[index]), utils.s_box)

                    round_key_x[0][col] = key_expanded[round][0][col] ^ rot_word[0] ^ rcon_table[0][round]
                    round_key_x[1][col] = key_expanded[round][1][col] ^ rot_word[1] ^ rcon_table[1][round]
                    round_key_x[2][col] = key_expanded[round][2][col] ^ rot_word[2] ^ rcon_table[2][round]
                    round_key_x[3][col] = key_expanded[round][3][col] ^ rot_word[3] ^ rcon_table[3][round]

                else:
                    val1_int = key_expanded[round][0][col] ^ round_key_x[0][col-1]
                    val2_int = key_expanded[round][1][col] ^ round_key_x[1][col-1]
                    val3_int = key_expanded[round][2][col] ^ round_key_x[2][col-1]
                    val4_int = key_expanded[round][3][col] ^ round_key_x[3][col-1]
                    #Wait to set the round_key_values since they would else get mo
                    round_key_x[0][col] = val1_int
                    round_key_x[1][col] = val2_int
                    round_key_x[2][col] = val3_int
                    round_key_x[3][col] = val4_int
            #Add new round key to list
            key_expanded.append(round_key_x)
        return key_expanded
    
    #Rotate a specific column up one from a 4x4 ndarray, used for the RotWord
    def rotate_column_up(self, key_array: np.ndarray, column):
        column_array = np.array([key_array[1][column], key_array[2][column], key_array[3][column], key_array[0][column]])
        return column_array


    def mix_columns(self, mix_array: np.ndarray):
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
                    mul_val = column[col]
                elif mix_columns_matrix[row][col] == 2:
                    mul_val = utils.multiply_by_2(column[col])
                elif mix_columns_matrix[row][col] == 3:
                    mul_val = utils.multiply_by_3(column[col])
                else:
                    raise RuntimeError("Could not find correct matrix value")
                temp_store.append(mul_val)
            #After loop XOR all values together
            total = temp_store[0] ^ temp_store[1] ^ temp_store[2] ^ temp_store[3]
            mixed_column[row] = total
        return mixed_column

    def inverse_mix_columns(self, mixed_array: np.ndarray):
        for i in range(4):
            input_array = np.array([mixed_array[0][i], mixed_array[1][i], mixed_array[2][i], mixed_array[3][i]])
            output = self.inverse_mix_column(input_array)
            mixed_array[0][i] = output[0]
            mixed_array[1][i] = output[1]
            mixed_array[2][i] = output[2]
            mixed_array[3][i] = output[3]

    #Used lookup tables instead of following the multiplication rule for runtime reasons
    def inverse_mix_column(self, column):
        mixed_column = np.empty(shape=4, dtype='<U4')
        #loop through matrix
        for row in range(4):
            temp_store = []
            for col in range(4):
                if inv_mix_columns_matrix[row][col] == 9:
                    mul_val = int(utils.lookup_table(column[col], utils.multiply_by_9),16)
                elif inv_mix_columns_matrix[row][col] == 11:
                    mul_val = int(utils.lookup_table(column[col], utils.multiply_by_11),16)
                elif inv_mix_columns_matrix[row][col] == 13:
                    mul_val = int(utils.lookup_table(column[col], utils.multiply_by_13),16)
                elif inv_mix_columns_matrix[row][col] == 14:
                    mul_val = int(utils.lookup_table(column[col], utils.multiply_by_14),16)
                else:
                    raise RuntimeError("Could not find correct matrix value")
                temp_store.append(mul_val)
            #After loop XOR all values together
            total = temp_store[0] ^ temp_store[1] ^ temp_store[2] ^ temp_store[3]
            mixed_column[row] = (hex(total))
        return mixed_column

    def sub_bytes(self, sub_array: np.ndarray):
        for pos, x in np.ndenumerate(sub_array):
            sub_array[pos[0]][pos[1]] = utils.lookup_table(hex(x), utils.s_box)

    def inverse_sub_bytes(self, sub_array: np.ndarray, s_box_dict: dict):
        for pos, x in np.ndenumerate(sub_array):
            #return hex(int(y_hex[2] + x_hex[2],16))
            x_hex, y_hex = s_box_dict[x]
            sub_array[pos[0]][pos[1]] = hex(int(y_hex[2] + x_hex[2],16))

    #This function supports all AES bit configurations
    def shift_rows(self, shift_array: np.ndarray):
        return shift_array.take((0,1,2,3,5,6,7,4,10,11,8,9,15,12,13,14)).reshape(4, 4)

    #This function supports all AES bit configurations
    def unshift_rows(self, shift_array: np.ndarray):
        return shift_array.take((0,1,2,3,7,4,5,6,10,11,8,9,13,14,15,12)).reshape(4, 4)


    #This function adds the round key or removes the round key depending
    #on if the array is being unencrypted or being encrypted
    def add_rm_round_key(self, array, round_key):
        return_array = np.empty(shape=(4,4), dtype='i')
        for i in range(4):
            for j in range(4):
                return_array[i][j] = array[i][j] ^ round_key[i][j]
        return return_array
    
    def convert_jpeg_to_base64(self, filename):
        #First convert jpeg to ppm, this format helps with reading the header

        loc = utils.convert_jpg_to_other(filename, "ppm")
        file1 = open(loc, 'rb')
        header_info = ""
        for i in range(3):
            header_info += file1.readline().decode("utf-8")
        file2 = open("temp/header.txt", "w")
        file2.write(header_info)
        file2.close()
        og = file1.read()
        encoded_string = base64.b64encode((og)).decode("utf-8")
        file1.close()

        return encoded_string

    def convert_base64_to_ppm(self, input_filename, output_filename):
        file1 = open("decrypt.txt", "r")
        base64_string = bytes.fromhex(file1.read())
        file1.close()
        trim_amount = 0
        if input_filename[len(input_filename)-3:] == "ppm":
            trim_amount = 3
        header_file = open("temp/header.txt", "r")
        header_string = header_file.read()
        header_file.close()
        #Write header file
        ppm_header_file = open(output_filename, "w")
        ppm_header_file.write(header_string)
        ppm_header_file.close()

        ppm_file = open(output_filename, "ab")
        ppm_file.write(base64_string)
        ppm_file.close()
        utils.show_image(output_filename)

    def convert_base64_to_jpeg(self, input_filename, output_filename):
        file1 = open("decrypt.txt", "r")
        base64_string = bytes.fromhex(file1.read())
        file1.close()
        trim_amount = 0
        if input_filename[len(input_filename)-3:] == "ppm":
            trim_amount = 3
        loc = os.getcwd() + "/temp/" + utils.find_file_name(output_filename)[:-4] + ".ppm"
        byte_string = base64.b64decode(base64_string)

        #You first need to create the decrypted ppm file,
        #Then convert the ppm back to jpeg
        header_file = open("temp/header.txt", "r")
        header_string = header_file.read()
        header_file.close()
        #Write header file
        ppm_header_file = open(loc, "w")
        ppm_header_file.write(header_string)
        ppm_header_file.close()
        #Write byte data back to ppm
        ppm_file = open(loc, "ab")
        ppm_file.write(byte_string)
        ppm_file.close()
        utils.show_image(loc)
        utils.convert_ppm_to_jpg(loc, output_filename)


    def encrypt_aes(self, input_filename, output_filename, key_phrase):
        #TODO Implement CBC option
        self.key_phrase = key_phrase
        key = self.convert_key()
        round_keys = self.create_round_keys(key)
        if len(round_keys) != self.rounds + 1:
            return ValueError("Wrong amount of round keys")
        if self.message == "":
            if input_filename[len(input_filename)-3:] == "jpg" or input_filename[len(input_filename)-4:] == "jpeg":
                self.message = self.convert_jpeg_to_base64(input_filename)
            else:
                self.read_txt_file(input_filename)
        message_blocks = self.convert_message()
        print("Encrypting " + utils.find_file_name(input_filename))
        for b_index in tqdm(range(len(message_blocks))):
            #First round
            message_blocks[b_index] = self.add_rm_round_key(message_blocks[b_index], round_keys[0])

            #Rounds 2-10
            for round in range(self.rounds - 1):
                start = time.process_time()
                self.sub_bytes(message_blocks[b_index])
                print("Sub Bytes: " + str(time.process_time() - start))
                start = time.process_time()
                message_blocks[b_index] = self.shift_rows(message_blocks[b_index])
                print("Shift Rows: " + str(time.process_time() - start))
                start = time.process_time()
                self.mix_columns(message_blocks[b_index])
                print("Mix Columns: " + str(time.process_time() - start))
                start = time.process_time()
                message_blocks[b_index] = self.add_rm_round_key(message_blocks[b_index], round_keys[round+1])
                print("Add Round Key: " + str(time.process_time() - start))
                print("temp")

            #Round 11
            self.sub_bytes(message_blocks[b_index])
            message_blocks[b_index] = self.shift_rows(message_blocks[b_index])
            message_blocks[b_index] = self.add_rm_round_key(message_blocks[b_index], round_keys[10])
        if input_filename[len(input_filename)-3:] == "jpg" or input_filename[len(input_filename)-4:] == "jpeg":
            self.convert_blocks_to_output(message_blocks, "decrypt.txt")
            self.convert_base64_to_ppm(input_filename, output_filename)
        else:
            self.convert_blocks_to_output(message_blocks, output_filename)
        print("Encrypted file is stored in " + output_filename)
        self.clear_temp_dir()

    def decyrpt_aes(self, input_filename, output_filename, key_phrase):
        self.key_phrase = key_phrase
        key = self.convert_key()
        round_keys = self.create_round_keys(key)
        #Used for inverse s box
        s_box_dict = self.create_inverse_s_box_dict()
        if len(round_keys) != self.rounds + 1:
            return ValueError("Wrong amount of round keys")
        encrypted_blocks = self.convert_input_to_blocks(input_filename)
        print("Decrypting " + utils.find_file_name(input_filename))
        for i in reversed(tqdm(range(len(encrypted_blocks)))):
            encrypted_blocks[i] = self.add_rm_round_key(encrypted_blocks[i], round_keys[10])
            encrypted_blocks[i] = self.unshift_rows(encrypted_blocks[i])
            self.inverse_sub_bytes(encrypted_blocks[i], s_box_dict)
            for round in reversed(range(self.rounds - 1)):
                encrypted_blocks[i] = self.add_rm_round_key(encrypted_blocks[i], round_keys[round+1])
                self.inverse_mix_columns(encrypted_blocks[i])
                encrypted_blocks[i] = self.unshift_rows(encrypted_blocks[i])
                self.inverse_sub_bytes(encrypted_blocks[i], s_box_dict)
            encrypted_blocks[i] = self.add_rm_round_key(encrypted_blocks[i], round_keys[0])

        self.convert_blocks_to_output(encrypted_blocks, "decrypt.txt")
        if output_filename[len(output_filename)-3:] == "jpg":
            self.convert_blocks_to_output(encrypted_blocks, "decrypt.txt")
            self.convert_base64_to_jpeg(input_filename, output_filename)
        else:
            self.convert_back_to_file("decrypt.txt", output_filename)
        print("Decrypted file is stored in " + output_filename)
        self.clear_temp_dir()

    def clear_temp_dir(self):
        mypath = os.getcwd()+"/temp"
        for root, dirs, files in os.walk(mypath):
            for file in files:
                os.remove(os.path.join(root, file))

    def convert_input_to_blocks(self, filename):
        encrypted_blocks = []
        blocks_string = ""
        if filename[len(filename)-3:] == "ppm":
            self.message = self.convert_jpeg_to_base64(filename)
            blocks_string = base64.b64decode(self.message).hex()
        else:
            file = open(filename, "r")
            lines = file.readlines()
            file.close()
            blocks_string = lines[0]
        if len(blocks_string) == 0:
            return LookupError(filename + " is empty")
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
        return encrypted_blocks

    def convert_blocks_to_output(self, message_blocks: list, filename):
        file = open(filename, "w")
        for block in message_blocks:
            temp_str = ""
            for i in range(4):
                for j in range(4):
                    temp_str += (f"0x{(block[j][i]):02x}")[2:]#(f"0x{(int(block[j][i],16)):02x}")[2:]
            file.write(temp_str)
        file.close()
    
    def convert_back_to_file(self, hex_filename, output_filename):
        file = open(hex_filename, "r")
        lines = file.readlines()
        file.close()
        line = lines[0]
        hex_list = self.unpad_hex(line)
        message = ""
        for i in range(1, len(hex_list), 2):
            if hex_list[i-1] == "0":
                hex_string = "0x" + hex_list[i]
            else:
                hex_string = "0x" + hex_list[i-1] + hex_list[i]
            message += chr(int(hex_string, 16))
        #print(message)
        file2 = open(output_filename, "w")
        file2.writelines(message)
        file2.close()
        
            


    #Similar to convert key but is not limited by block size
    def convert_message(self):
        message_blocks = []#np.empty()
        hex_list = [hex(ord(c)) for c in list(self.message) if True]
        if len(self.message) * 8 < self.block_size:
            self.pad_hex(hex_list)
            #Convert it back to integers
            hex_list  = [int(c, 16) for c in hex_list if True]
            message_blocks.append(np.array(hex_list).reshape(4,4).swapaxes(0,1))
        elif len(self.message) * 8 >= self.block_size:
            #Pads the message if it is not in 128 bit multiples
            if (len(self.message) * 8) % self.block_size == 0:
                blocks_total = int((len(self.message) * 8) / self.block_size)
                for i in range(blocks_total):
                    block = hex_list[i*16:(i+1)*16]
                    #Convert it back to integers
                    block  = [int(c, 16) for c in block if True]
                    message_blocks.append(np.array(block).reshape(4,4).swapaxes(0,1))
            else:
                filled_blocks_total = math.floor((len(self.message) * 8) / self.block_size)
                #Filled all full blocks
                for i in range(filled_blocks_total):
                    block = hex_list[i*16:(i+1)*16]
                    message_blocks.append(np.array(block).reshape(4,4).swapaxes(0,1))
                tail_block = hex_list[(i+1)*16:]
                self.pad_hex(tail_block)
                #Convert it back to integers
                tail_block  = [int(c, 16) for c in tail_block if True]
                message_blocks.append(np.array(tail_block).reshape(4,4).swapaxes(0,1))
        
        return message_blocks

    def convert_key(self):
        hex_list = [hex(ord(c)) for c in list(self.key_phrase) if True]
        if len(self.key_phrase) * 8 < self.block_size:
            self.pad_hex(hex_list)
        elif len(self.key_phrase) * 8 > self.block_size:
            raise ValueError("Key too large for block size")
        hex_list = [int(c, 16) for c in list(hex_list) if True]
        #Convert values from hex to int
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
        bytes_left: int = int(bits_left / 8)
        #For the PKCS#7 Padding you add the bytes left as a hex value to all the empty spaces
        hex_to_append = hex(bytes_left)
        for i in range(bytes_left):
            hex_list.append(hex_to_append)
    #Undoes PKCS#7 padding
    def unpad_hex(self, hex_list: list):
        hex_len = hex_list[len(hex_list)-1]
        padding_len = int(hex_len, 16)
        rev_list = hex_list[::-1]
        #Check to see if hex list is padded
        is_padded = True
        for i in range(3, padding_len*2, 2):
            if (rev_list[i-3], rev_list[i-2]) != (rev_list[i-1], rev_list[i]):
                is_padded = False
                break
        if is_padded:
            for i in range(padding_len * 2):
                hex_list = list(hex_list)
                hex_list.pop()
        return hex_list



