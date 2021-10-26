from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_256
import pickle

class Protocol:
    """
    A class for our encryption protocol.
    ...

    Attributes:
    _SessionKey (byte[]): session key for symmetric encryption
    _BootstrapKey (byte[]): key for encryption of DHE key establishment. based off of shared secret
    _Mode (String): prototocol mode (None, "Client" or "Server")
    _DHExponent (int): our DH exponent. to be 'forgotten' after establishment of session key
    _AuthNonceLen (int) CONSTANT: the constant length of generate nonces in the protocol
    _g (int) CONSTANT: our protocol's DH generator
    _p (int) CONSTANT: our protocol's DH prime
    _InitVal (bytes[]): a String identifyign our protocol's initiation message
    """

    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    # TODO: @Brendon and Joshua add DH constants (g and p)
    def __init__(self):
        """initializes all variables to None"""
        self._SessionKey = None
        self._BootstrapKey = None
        self._Mode = None
        self._DHExponent = None
        self._AuthNonceLen = 16
        self._g = None
        self._p = None
        self._InitVal = b'Protocol initiation message'
        pass

    def SetBootstrapKey(self, AuthNonce, secret):
        """
        Creates a key from the shared secret and nonce to encrypt the DH exchange
        Parameters:
        AuthNonce (byte[]): Random nonce to hash with secret string
        secret (String): Secret string of arbitrary length
        """
        
        # h(nonce|secret)
        hash_object = SHA3_256.new(data=AuthNonce)
        secret_bytes = str.encode(secret)
        hash_object.update(secret_bytes)

        long_key = hash_object.digest()

        self._BootstrapKey = [long_key[i] ^ long_key[i+16] for i in range(16)] # converts 32B hash to 16B key

    def SetClientMode(self):
        """Sets mode to client"""
        self._Mode = "Client"
    
    def SetServerMode(self):
        """Sets mode to server"""
        self._Mode = "Server"
        
    def GenerateNonce(self):
        """Generates a cryptographically secure random nonce"""
        return get_random_bytes(self._AuthNonceLen)

    # TODO: @Brendon and Joshua IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, secret):
        """Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)"""
        return ""

    def IsMessagePartOfProtocol(self, message):
        """Checking if a received message is part of your protocol (called from app.py)"""
        if message.find(self._InitVal) == 0:
            return True
        return False

    # TODO: @Brendon and Joshua IMPLEMENT THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    def ProcessReceivedProtocolMessage(self, message):
        """
        Processing protocol message

        Raises:
        Exception: if authentication fails
        """
        pass

    # TODO: @Brendon calculate DH shared secret
    def SetSessionKey(self, OtherPublicDH):
        """
        Setting the key for the current session
        
        Parameters:
        OtherPublicDH: g^a mod p from the other party for diffie hellman

        Raises:
        Exception: if self._DHExponent == None
        """
        self._SessionKey = "" # use g^a mod p and our DH exponent to calculate session key
        self._BootstrapKey = None # no longer need this key
        pass

    # TODO: @sanjeev IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    def EncryptAndProtectMessage(self, plain_text):
        """
        Encrypting messages and tag
        RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
        """
        cipher_text = plain_text
        return cipher_text

    # TODO: @sanjeev IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    def DecryptAndVerifyMessage(self, cipher_text):
        """
        Decrypting and verifying messages
        RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
        """
        plain_text = cipher_text
        return plain_text
