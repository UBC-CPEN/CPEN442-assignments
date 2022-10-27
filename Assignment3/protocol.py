import Crypto.Hash.HMAC
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._skey = None
        self._ikey = None

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        return ""


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return False


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        pass


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, skey, ikey):
        self._skey = skey
        self._ikey = ikey
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        ctrcipher = AES.new(self._skey, AES.MODE_CTR)
        hmac = Crypto.Hash.HMAC.new(self._ikey)

        cipher_text = ctrcipher.nonce + ctrcipher.encrypt(plain_text.encode('utf-8'))

        hmac.update(plain_text.encode('utf-8'))
        cipher_text += hmac.digest()

        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        ctrcipher = AES.new(self._skey, AES.MODE_CTR, nonce=cipher_text[:8])
        hmac = Crypto.Hash.HMAC.new(self._ikey)

        plain_bytes = ctrcipher.decrypt(cipher_text[8:-16])

        hmac.update(plain_bytes)
        hmac.verify(cipher_text[-16:])

        return plain_bytes.decode('utf-8')

if __name__ == "__main__":

    #post key establishment test
    testProtocol = Protocol()
    testInput = "The quick brown fox jumps over the lazy dog"
    skey = Crypto.Random.get_random_bytes(16)
    ikey = Crypto.Random.get_random_bytes(16)
    testProtocol.SetSessionKey(skey, ikey)
    output = testProtocol.EncryptAndProtectMessage(testInput)
    input = testProtocol.DecryptAndVerifyMessage(output)
    assert input == testInput