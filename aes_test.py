import unittest
from aes import *

class TestAESEncyrptionFunctions(unittest.TestCase):
    def setUp(self):
        pass
    def test_sub_from_s_box(self):
        aes = AES("Test$SubBox1234!")
        output = aes.sub_from_s_box('8e')
        self.assertEqual('0x19', output)

        output = aes.sub_from_s_box('00')
        self.assertEqual('0x63', output)

        output = aes.sub_from_s_box('f0')
        self.assertEqual('0x8c', output)

        output = aes.sub_from_s_box('0f')
        self.assertEqual('0x76', output)

        output = aes.sub_from_s_box('69')
        self.assertEqual('0xf9', output)

        output = aes.sub_from_s_box('cb')
        self.assertEqual('0x1f', output)