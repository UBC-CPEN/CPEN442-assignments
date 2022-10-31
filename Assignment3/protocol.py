from __future__ import generator_stop
import Crypto.Hash.HMAC
from Crypto.Cipher import AES
import time
import os

# generator and modulus chosen from rfc3526, specifically groups #14 and #15. 
# https://www.ietf.org/rfc/rfc3526.txt
generator = 2
modulus = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF

# group 15 in rfc3526
generatorP = 2
modulusP = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF



class Protocol:

    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._skey = None
        self._ikey = None
        self.isClient = False
        self.sharedSecret = None
        self.timestamp = 0
        self.clientsConnectionStates = {} # populated by Server only, unused by Client
        self.keysDict = {}

    def setSharedSecret(self,ss):
        self.sharedSecret = ss

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    #Only called by clients
    def GetProtocolInitiationMessage(self, ip_address):
        assert self.sharedSecret is not None

        cipher = AES.new(self.sharedSecret, AES.MODE_CCM)
        # the crypto library suggests using the os random number generator and generally considers it to be a cryptographically secure random number generator: 
        # link here: https://cryptography.io/en/latest/random-numbers/
        # as for choice on the exponent bit-size, there was a section in the rfc document used above that said that the exponent should be roughly 2x the bit-strength of the group we chose (last paragraph introduction section)
        # by looking at the table, group 14 had a bit strength of 110, group 15 had 130, thus I chose 256 as the exponent bit-size for both. 

        a = os.urandom(256)
        aP = os.urandom(256)
        partialEncKey = pow(generator,a,modulus)
        partialIntKey = pow(generatorP,aP,modulusP)
        self.keysDict[ip_address] = (partialEncKey,partialIntKey)
        self.timestamp = int(time.time())
        timestamp = str(self.timestamp)
        data = "CLNT"  + timestamp + "|"+ str(partialEncKey) + "|" + str(partialIntKey)

        ciphertext, MAC_tag = cipher.encrypt_and_digest(data.encode('utf-8'))

        # realized that the mac_tag that is acquired from the encrypt_and_digest function is actually a second level mac.
        # effectively, the encrypt function (to my understanding) replicates precisely what the entire thing does, aka what AES-CCM does in this case, and then encrypt_and_digest adds a mac to that scheme
        # simply due to the fact that every single mode has an encrypt_and_digest function that can be used, 
        return ciphertext + MAC_tag


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self,ip_address):
        val = self.clientsConnectionStates.get(ip_address)
        if val is None:
            self.clientsConnectionStates.update(ip_address, False)
            return True
        return val

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message, isClient, ip_address):
        assert self.sharedSecret is not None
        assert len(message>16)
        assert ip_address is not None
        cipher = AES.new(self.sharedSecret, AES.MODE_CCM)
        ciphertext = message[:-16]  # I'm Alice represents first 9 bytes, last 16 bytes are the MAC
        mac = message[-16:]
        plaintext = cipher.decrypt_and_verify(ciphertext,mac)
        # get the timestamp
        first, second = plaintext.split('|', 1)
        timestamp = int(first[4:])
        if isClient:
            # set the new information provided by the server accordingly
            if first[:4] != "SRVR":
                raise Exception("SRVR tag not found, could not complete key establishment")
            # verify timestamp
            if self.timestamp + 1 == timestamp:
                raise Exception("Timestamp does not match, could not complete key establishment")
            BEncPKey, BIntPKey = second.split('|')
            (a,aP) = self.keysDict[ip_address]
            self.keysDict[ip_address] = (pow(int(BEncPKey),a,modulus), pow(int(BIntPKey),aP, modulusP))
            return None
        else:
            if first[:4] != "CLNT":
                raise Exception("CLNT tag not found, could not complete key establishment")
            cipher = AES.new(self.sharedSecret, AES.MODE_CCM)
            # the crypto library suggests using the os random number generator and generally considers it to be a cryptographically secure random number generator:
            # link here: https://cryptography.io/en/latest/random-numbers/
            # as for choice on the exponent bit-size, there was a section in the rfc document used above that said that the exponent should be roughly 2x the bit-strength of the group we chose (last paragraph introduction section)
            # by looking at the table, group 14 had a bit strength of 110, group 15 had 130, thus I chose 256 as the exponent bit-size for both.
            b = os.urandom(256)
            bP = os.urandom(256)
            partialEncKey = pow(generator, b, modulus)
            partialIntKey = pow(generatorP, bP, modulusP)
            AEncPKey,AIntPKey = second.split('|')
            self.keysDict[ip_address] = (pow(int(AEncPKey),b,modulus),pow(int(AIntPKey),bP,modulusP))
            data = "SRVR" + str(timestamp+1) + "|" + str(partialEncKey) + "|" + str(partialIntKey)

            ciphertext, MAC_tag = cipher.encrypt_and_digest(data.encode('utf-8'))
            return ciphertext+MAC_tag
            # parse client info, return updated keys

    # set self.timeStamp to the timestamp we received so we can then calculate timeStamp + 1 in the server's response message.


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

        hmac.update(cipher_text)
        cipher_text += hmac.digest()

        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        ctrcipher = AES.new(self._skey, AES.MODE_CTR, nonce=cipher_text[:8])
        hmac = Crypto.Hash.HMAC.new(self._ikey)

        hmac.update(cipher_text[:-16])
        hmac.verify(cipher_text[-16:])

        plain_bytes = ctrcipher.decrypt(cipher_text[8:-16])

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