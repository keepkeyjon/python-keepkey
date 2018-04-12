# RUN: python %s
import os
import binascii
import common
import hashlib
import sys
import unittest
from keepkeylib import flash_hash

if sys.version_info < (3,6):
    import sha3

from keepkeylib import messages_pb2 as messages

class TestBasic(common.KeepKeyTest):

    def test_flash_hash_protocol_python(self):
        test_challenge = binascii.unhexlify('d9c8640a60080d36a02cae710a1cfb4c6c3e1ca2bb9812003d3d32eeeef93084')
        test_response = binascii.unhexlify('3c8cf675462465180405ae8aaaa40e4b753e2b5d9045262468af60d223f60bb7')
        #get the bootloader fingerprint
        ret1 = self.client.call(messages.FlashHash(address=0x08020000, length=256*1024, challenge=''))
        fingerprint = binascii.hexlify(ret1.data)
        #calculate expected
        asset = flash_hash.fetch_asset(fingerprint)
        python_response = flash_hash.hash_asset(test_challenge, fingerprint, length=256*1024).digest()
        self.assertEqual(test_response, python_response)

    def test_flash_hash_protocol_on_device(self):
        test_challenge = binascii.unhexlify('d9c8640a60080d36a02cae710a1cfb4c6c3e1ca2bb9812003d3d32eeeef93084')
        test_response = binascii.unhexlify('3c8cf675462465180405ae8aaaa40e4b753e2b5d9045262468af60d223f60bb7')
        #get the bootloader fingerprint
        ret1 = self.client.call(messages.FlashHash(address=0x08020000, length=256*1024, challenge=''))
        fingerprint = binascii.hexlify(ret1.data)
        #get the response from the device
        ret2 = self.client.call(messages.FlashHash(address=0x08020000, length=256*1024, challenge=test_challenge))
        device_response = ret2.data
        self.assertEqual(device_response, test_response) 

    def test_flash_hash_protocol_end_to_end(self):
        #test against v1.0.0 bootloader
        vectors = [('33bf7ae53e409309c4cbff048c17dd672c6b22615ddad1ab04177ee41f0928f9',
                    'c0b345b9bfbc29a2063f34c4f02c91d800e07de95a11120e557212fe495a253a'),
                   ('9710dc2de304eacad3c680e35c8c82128dda450c49e2d4e46885700bf7d28abd',
                    '91de1582cce79bea8746253436a3907d37be83424cfe23f5126ba6e28c2b0801'),
                   ('4b214380babd8dbf8e67d99da6e556e6ed8c785a72346c08996a3f6d4436cae6',
                    '79459941e5995ec72c0d549e0090e9720f3fa24a905113429181c22969aa5fb0'),
                   ('adf5ca4f0f1d753b988cc38ae35559a3b58e53496f1216f9a95ae894c115cfa9',
                    'd1e75203702bf356bfce49826c8fe1972d3eff1cdd428a73e8fc41cfd1b45307'),
                   ('5f999dc6d6cbf69619b64972cfe7fae9fa8878d6165be18502ea0482d8b535a0',
                    'cc1700118930e683ea6ecc07a7c5a5a013ce2ec43119ef693b8a61400f9d3d26'),
                   ('cb9a0d1cd12ee73e5d8969d611ab26e388bed2280b53cd6482d11c45a7ed2725',
                    '3c1bc6bc356607874e6ffa0eddf8524a81c004ae1001411406cfadab8f2d148c'),
                   ('db83e3ec594e32474edd108fa0ed8090ea9d43dce291586a42addc81f12ad930',
                    '93be74ea8f272f6e91dd4e66f10674de45fc339792d7f783fd7bbcb3983b8a55'),
                   ('292980a9010f801acfcf283a81449a7d93268600996ba29889424eb3b3c970b4',
                    '4ceb3a7df368aefb39ded4314e317251fe42e099ffe87263f62545963d97f79d'),
                   ('eff3998a14e0c324fd047f591b09f1bb55431c9adee1113d8bd2bb33387d03ed',
                    '6586c7cfee7c762a40c3568a1780376d96fae3f266430a8ee9bda580d089b185'),
                   ('424662922ee25da2e4516e92c2ee0c992f79b0ebbef37245c41cdb375c07d4dd',
                    'e8348e5e7fe0a0f848ce10b4ae866c13b4637fa69fe89ee26f0dd373702deed5')]

        for test_challenge, test_response in vectors:
            test_challenge = binascii.unhexlify(test_challenge)
            #get the bootloader fingerprint
            ret1 = self.client.call(messages.FlashHash(address=0x08020000, length=1024*256, challenge=''))
            fingerprint = binascii.hexlify(ret1.data)
            #calculate the expected response
            asset = flash_hash.fetch_asset(fingerprint)
            python_response = binascii.hexlify(flash_hash.hash_asset(test_challenge, fingerprint).digest())
            self.assertEqual(python_response, test_response)    
            #send challenge to device
            ret2 = self.client.call(messages.FlashHash(address=0x08020000, length=1024*256, challenge=test_challenge))
            device_response = binascii.hexlify(ret2.data)
            self.assertEqual(device_response, python_response)

if __name__ == '__main__':
    unittest.main()
