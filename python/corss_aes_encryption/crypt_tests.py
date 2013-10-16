'''
Created on Oct 15, 2013

@author: georgilambov
'''
import unittest
from corss_aes_encryption.crypt import AESEncryption


class AESEncryptionTest(unittest.TestCase):

    def setUp(self):
        global aes_encryption, prod_key
        aes_encryption = AESEncryption()
        aes_encryption.key = "MySecretKeyMustBe32CharactersLng"
        prod_key = "qj@p69E[s!R/?F*4SG#VOlP;)4E![4#2"

    def tearDown(self):
        pass

    def test_key_size(self):
        self.assertEqual(len(aes_encryption.key.encode("utf-8")), 32)

    def test_prod_key(self):
        self.assertEqual(len("qj@p69E[s!R/?F*4SG#VOlP;)4E![4#2".encode("utf-8")), 32)

    def test_decode_one_char_from_objectivec(self):
        hashv = "BiIm9m5vLXyHpTC7uZcbow=="
        decrypted = aes_encryption.decode(hashv)
        self.assertEqual(decrypted, "a")

    def test_decode_exact_block_from_objectivec(self):
        block_value = "aaaaaaaaaaaaaaa"
        self.assertEqual(len(block_value.encode("utf-8")), 15)
        hashv = "ENMRNjI1Z1OZoG1H6jdhjQ=="
        decrypted = aes_encryption.decode(hashv)
        self.assertEqual(decrypted, block_value)

    def test_decode_multiple_blocks_from_objectivec(self):
        block_value = "{\"progress\": [], \"goods\": {\"coins\": 100000, \"diamonds\": 100000}, \"inventory\": {\"characters\": [], \"costumes\": []}}"
        self.assertEqual(len(block_value.encode("utf-8")), 113)
        hashv = "9ufo4Hw8QHddnaBf6YRSrzsRTsEPOf2XlYM0LEWROkT1FNi5TAd+ickmBPhsOy3Oibjb3O7pswBEq+TRvdr1ArMGybkTQoXuzain7WPzjURM40lBaNGWKNiV63i4Csphz9E9U0CES/p03mVpX44xwM5f/4fAC7BRn7eKuLlBkJ8="
        decrypted = aes_encryption.decode(hashv)
        self.assertEqual(decrypted, block_value)

    def test_decode_with_production_key(self):
        block_value = "{\"progress\": [], \"goods\": {\"coins\": 100000, \"diamonds\": 100000}, \"inventory\": {\"characters\": [], \"costumes\": []}}"
        self.assertEqual(len(block_value.encode("utf-8")), 113)
        hashv = "qe7ysJsA5U096Y2b/U89tzvyyytvCOsFQTnDJqr6nrgBhwOAynt1ypiboXLrfbTSSQzC8p9aG4lwZs+G5KZ3R4wCJTB0D5E721icMqd3tP/aWsKtY6Og5BibjFMg9/faZfe9EqIaGXBd8TG7IzC16gNDDEInLB5ho53Ix32oFvA="
        aes_encryption.key = prod_key
        decrypted = aes_encryption.decode(hashv)
        self.assertEqual(decrypted, block_value)

    def test_encode_one_char(self):
        encrypted = aes_encryption.encode("a")
        decrypted = aes_encryption.decode(encrypted)
        self.assertEqual("a", decrypted)

    def test_encode_multiple_blocks(self):
        block_value = "{\"progress\": [], \"goods\": {\"coins\": 100000, \"diamonds\": 100000}, \"inventory\": {\"characters\": [], \"costumes\": []}}"
        encrypted = aes_encryption.encode(block_value)
        objectivec_hashv = "9ufo4Hw8QHddnaBf6YRSrzsRTsEPOf2XlYM0LEWROkT1FNi5TAd+ickmBPhsOy3Oibjb3O7pswBEq+TRvdr1ArMGybkTQoXuzain7WPzjURM40lBaNGWKNiV63i4Csphz9E9U0CES/p03mVpX44xwM5f/4fAC7BRn7eKuLlBkJ8="
        decrypted = aes_encryption.decode(encrypted)
        print objectivec_hashv
        print encrypted
        self.assertEqual(objectivec_hashv, encrypted)
        self.assertEqual(block_value, decrypted)

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
