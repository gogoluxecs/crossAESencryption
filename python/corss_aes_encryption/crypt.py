import binascii
import StringIO
from Crypto.Cipher import AES
import base64


class PKCS7Encoder:

    """
    https://gist.github.com/chrix2/4171336
    """

    def __init__(self, k=16):
        self.k = k

    # # @param text The padded text for which the padding is to be removed.
    # @exception ValueError Raised when the input padding is missing or corrupt.

    def decode(self, text):
        """
        Removes the PKCS#7 padding from a text string
        """

        nl = len(text)
        val = int(binascii.hexlify(text[-1]), self.k)

        if val > self.k:
            raise ValueError("Input is not padded or padding is corrupt"
                             )

        l = nl - val
        return text[:l]

    # # @param text The text to encode.

    def encode(self, text):
        """
        Pads an input string according to PKCS#7
        """

        l = len(text)
        output = StringIO.StringIO()
        val = self.k - l % self.k
        for _ in xrange(val):
            output.write("%02x" % val)
        return text + binascii.unhexlify(output.getvalue())


class AESEncryption:

    def __init__(self, key=None, BS=None):
        self.key = key
        self.pkcs7 = PKCS7Encoder()
        self.BS = (BS if BS else None)

    def decode(self, encodedEncrypted, BS=16):
        """
        Decrypts data with AES.
        """

        if self.key is None:
            raise ValueError("key is required")

        BS = (self.BS if self.BS else BS)
        unpad = lambda s: s[0:-ord(s[-1])]
        cipher = AES.new(self.key)

        decrypted = \
            cipher.decrypt(base64.b64decode(encodedEncrypted))[:BS]

        for i in range(1, len(base64.b64decode(encodedEncrypted)) / BS):
            cipher = AES.new(self.key, AES.MODE_CBC,
                             base64.b64decode(encodedEncrypted)[(i - 1)
                             * BS:i * BS])
            decrypted += \
                cipher.decrypt(base64.b64decode(encodedEncrypted)[i
                               * BS:])[:BS]

        return unpad(decrypted.strip())

    def encode(self, raw, BS=16):
        """
        Encrypts data with AES.
        """

        if self.key is None:
            raise ValueError("key is required")

        BS = (self.BS if self.BS else BS)

        cipher = AES.new(self.key)
        encoded = self.pkcs7.encode(raw)
        encrypted = cipher.encrypt(encoded)

        return base64.b64encode(encrypted)

