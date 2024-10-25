import hashlib
from pathlib import Path
from reedsolo import RSCodec
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


class DataCodec:

    def __init__(self, password: str) -> None:
        self.password = password
        self.ecc_len = 8
        self.key = hashlib.sha256(password.encode('utf-8')).digest()

    def _encrypt(self, data: bytes) -> bytes:

        print('encrypting...')

        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))

        print('encryption done')
        return iv + encrypted_data

    def _decrpyt(self, data: bytes) -> bytes:

        print('decrypting...')

        iv = data[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(data[16:])
        decrypted_data = unpad(decrypted_padded, AES.block_size)

        print('decryption done')
        return decrypted_data

    def _encode_ecc(self, data: bytes) -> bytes:

        print('ecc encoding...')
        rs = RSCodec(self.ecc_len)
        rt = bytes(rs.encode(data))
        print('ecc encode done')

        return rt

    def _decode_ecc(self, data: bytes) -> bytes:

        print('ecc decoding...')
        rs = RSCodec(self.ecc_len)
        rt = bytes(rs.decode(data)[0])
        print('ecc decode done')

        return rt

    def encode(self, data: bytes) -> bytes:

        encrypted_data = self._encrypt(data)
        ecc_encoded_data = self._encode_ecc(encrypted_data)
        return ecc_encoded_data

    def decode(self, data: bytes) -> bytes:

        ecc_decoded_data = self._decode_ecc(data)
        decrypted_data = self._decrpyt(ecc_decoded_data)
        return decrypted_data


def calculate_checksum(data: bytes) -> str:
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def test_encode(file: str, password: str) -> str:
    data = Path(file).read_bytes()
    checksum = calculate_checksum(data)
    print(f'Checksum of original data: {checksum}')

    codec = DataCodec(password)
    encoded_data = codec.encode(data)

    with open('encoded_data.bin', 'wb') as f:
        f.write(encoded_data)
        print(f'Encoded data written to encoded_data.bin')

    return checksum

def test_decode(file: str, password: str) -> str:
    data = Path(file).read_bytes()

    codec = DataCodec(password)
    decoded_data = codec.decode(data)
    checksum = calculate_checksum(decoded_data)
    print(f'Checksum of decoded data: {checksum}')

    with open('total_decoded.zst', 'wb') as f:
        f.write(decoded_data)
    return checksum


checksum_1 = test_encode('total.zst', 'mybirthday')
checksum_2 = test_decode('encoded_data.bin', 'mybirthday')

if checksum_1 == checksum_2:
    print('Checksums matched :)')
else:
    print('Checksums did not match :(')
