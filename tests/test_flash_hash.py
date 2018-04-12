# RUN: python %s
import binascii
import common
import hashlib
import sys
import unittest

if sys.version_info < (3,6):
    import sha3

from keepkeylib import messages_pb2 as messages

class TestBasic(common.KeepKeyTest):

    def test_flash_hash1(self):
        ret1 = self.client.call(messages.FlashHash(address=0x08004000, length=32, challenge=''))
        ret2 = self.client.call(messages.FlashHash(address=0x08004000, length=32, challenge=''))
        self.assertEqual(binascii.hexlify(ret1.data), binascii.hexlify(ret2.data))

    def test_flash_hash2(self):
        ret1 = self.client.flash_hash(address=0x08004000, length=32, challenge='')
        ret2 = self.client.flash_hash(address=0x08004000, length=32, challenge='')
        self.assertEqual(binascii.hexlify(ret1), binascii.hexlify(ret2))

    def test_flash_hash_challenge1(self):
        ret1 = self.client.call(messages.FlashHash(address=0x08004000, length=32, challenge='foxy foxy fox'))
        ret2 = self.client.call(messages.FlashHash(address=0x08004000, length=32, challenge='foxy foxy fox'))
        ret3 = self.client.call(messages.FlashHash(address=0x08004000, length=32, challenge='hungry hungry hound'))
        self.assertEqual(binascii.hexlify(ret1.data), binascii.hexlify(ret2.data))
        self.assertNotEqual(binascii.hexlify(ret1.data), binascii.hexlify(ret3.data))

    def test_flash_hash_challenge2(self):
        ret1 = self.client.flash_hash(address=0x08004000, length=32, challenge='foxy foxy fox')
        ret2 = self.client.flash_hash(address=0x08004000, length=32, challenge='foxy foxy fox')
        ret3 = self.client.flash_hash(address=0x08004000, length=32, challenge='hungry hungry hound')
        self.assertEqual(binascii.hexlify(ret1), binascii.hexlify(ret2))
        self.assertNotEqual(binascii.hexlify(ret1), binascii.hexlify(ret3))

    # TODO: test bounds checks on python side, and on device side

if __name__ == '__main__':
    unittest.main()
