import unittest
from aes import *

class TestAESEncyrptionFunctions(unittest.TestCase):
    def setUp(self):
        pass
    def test_lookup_table_s_box(self):
        aes = AES("Test$SubBox1234!", "temp")
        output = utils.lookup_table('8e', utils.s_box)
        self.assertEqual('0x19', output)

        output = utils.lookup_table('00', utils.s_box)
        self.assertEqual('0x63', output)

        output = utils.lookup_table('f0', utils.s_box)
        self.assertEqual('0x8c', output)

        output = utils.lookup_table('0f', utils.s_box)
        self.assertEqual('0x76', output)

        output = utils.lookup_table('69', utils.s_box)
        self.assertEqual('0xf9', output)

        output = utils.lookup_table('cb', utils.s_box)
        self.assertEqual('0x1f', output)
    def test_inverse_sub_from_s_box(self):
        aes = AES("Test$SubBox1234!", "temp")
        output = aes.sub_from_s_box('0xd3')
        self.assertEqual('0x66', output)

        output = aes.sub_from_s_box('0xb8')
        self.assertEqual('0x6c', output)

        output = aes.sub_from_s_box('0x7a')
        self.assertEqual('0xda', output)

    def test_mix_columns(self):
        aes = AES("Test$SubBox1234!", "temp")
        input_array = [['0xd4', '0xe0', '0xb8', '0x1e'],
                 ['0xbf', '0xb4', '0x41', '0x27'],
                 ['0x5d', '0x52', '0x11', '0x98'],
                 ['0x30', '0xae', '0xf1', '0xe5']]
        
        match_array = [['0x4', '0xe0', '0x48', '0x28'],
                 ['0x66', '0xcb', '0xf8', '0x6'],
                 ['0x81', '0x19', '0xd3', '0x26'],
                 ['0xe5', '0x9a', '0x7a', '0x4c']]
        output_array = input_array.copy()
        aes.mix_columns(output_array)
        self.assertEqual(match_array, output_array)
    def test_mix_column(self):
        aes = AES("Test$SubBox1234!", "temp")
        mixed_column = aes.mix_column(np.array(['0xd4', '0xbf', '0x5d', '0x30']))
        print(mixed_column)
        match_column = ['0x4', '0x66', '0x81', '0xe5']
        self.assertEqual(list(mixed_column), match_column)
    def test_inverse__mix_columns(self):
        aes = AES("Test$SubBox1234!", "temp")
        input_array = [['0xd4', '0xe0', '0xb8', '0x1e'],
                 ['0xbf', '0xb4', '0x41', '0x27'],
                 ['0x5d', '0x52', '0x11', '0x98'],
                 ['0x30', '0xae', '0xf1', '0xe5']]
        output_array = input_array.copy()
        aes.mix_columns(output_array)
        original_array = output_array.copy()
        aes.inverse_mix_columns(original_array)
        self.assertEqual(input_array, original_array)
    def test_inverse_mix_column(self):
        aes = AES("Test$SubBox1234!", "temp")
        mixed_column = aes.mix_column(np.array(['0xd4', '0xbf', '0x5d', '0x30']))
        print(mixed_column)
        #match_column = ['0x4', '0x66', '0x81', '0xe5']
        original_column = aes.inverse_mix_column(mixed_column)
        self.assertEqual(list(original_column), ['0xd4', '0xbf', '0x5d', '0x30'])
