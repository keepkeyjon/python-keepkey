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

    def off_test_flash_write(self):
        data = b"\xde\xad\xbe\xef"
        ret = self.client.call(messages.FlashWrite(address=0x08004000,
                                                   data=data))
        exp = hashlib.sha3_256(data).hexdigest()
        self.assertEqual(binascii.hexlify(ret.data), exp)

    def off_test_flash_write2(self):
        data = "wasabi"
        ret = self.client.flash_write(address=0x08004000,
                                      data=binascii.hexlify(data))
        exp = hashlib.sha3_256(data).hexdigest()
        self.assertEqual(binascii.hexlify(ret), exp)

    def off_test_flash_write_long(self):
        # Fill Sectors 1-4 with 0-F repeating, followed by "some extra stuff"
        data = ("0123456789ABCDEF" * (1024 / 16 * 3)) + "some extra stuff"
        ret = self.client.call(messages.FlashWrite(address=0x08004000,
                                                   data=binascii.hexlify(data)))
        exp = hashlib.sha3_256(chunk).hexdigest()
        self.assertEqual(binascii.hexlify(ret), exp)

    def off_test_flash_write_long2(self):
        data = ("foxfoxfoxfoxfoxy" * (1024 / 16 * 3)) + "overspill"
        ret = self.client.flash_write(address=0x08004000,
                                      data=binascii.hexlify(data))
        exp = hashlib.sha3_256(chunk).hexdigest()
        self.assertEqual(binascii.hexlify(ret), exp)

    # TODO: test bounds checks on python side, and on device side

if __name__ == '__main__':
    unittest.main()
