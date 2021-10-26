from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA3_256
from datetime import datetime
import pickle

class Protocol:
    """
    A class for our encryption protocol.
    ...

    Attributes:
    _SessionKey (byte[]): session key for symmetric encryption
    _BootstrapKey (byte[]): key for encryption of DHE key establishment. based off of shared secret
    _ServerMode (bool): prototocol mode, server if true, client otherwise
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
        self._ServerMode = True
        self._DHExponent = None
        self._AuthNonceLen = 16
        self._g = None
        self._p = None
        self._ClientInitVal = b'Client protocol initiation message'
        self._ServerInitVal = b'Server protocol initiation message'
        self._MWait = None
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
        self._ServerMode = False
    
    def SetServerMode(self):
        """Sets mode to server"""
        self._ServerMode = True
        
    def GenerateNonce(self):
        """Generates a cryptographically secure random nonce"""
        return get_random_bytes(self._AuthNonceLen)

    # TODO: @Brendon and Joshua IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, secret):
        """Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)"""
        msg = {}
        AuthNonce = self.GenerateNonce()
        if self._ServerMode:
            InitMessage = self._ServerInitVal
        else:
            InitMessage = self._ClientInitVal

        self.SetBootstrapKey(AuthNonce, secret)
        msg["AuthNonce"] = AuthNonce
        timestamp = datetime.today().timestamp()
        ts_bytes = str(timestamp).encode()

        msg["EncryptedTS"] = ts_bytes # TODO: @Sanjeev encrypt with bootstap key
        msg["DiffieHellman"] = [] # TODO: @Brendon add DH part key here

        self._MWait = datetime.now()
        
        return InitMessage + pickle.dumps(msg)

    def IsMessagePartOfProtocol(self, message):
        """Checking if a received message is part of your protocol (called from app.py)"""
        if self._ServerMode == True and message.find(self._ClientInitVal) == 0:
            return True
        if self._ServerMode == False and message.find(self._ServerInitVal) == 0:
            return True
        return False

    # TODO: @Brendon and Joshua IMPLEMENT THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    def ProcessReceivedProtocolMessage(self, message, secret):
        """
        Processing protocol message

        Raises:
        Exception: if authentication fails
        """
        message = message[len(self._ServerInitVal):]
        msg = pickle.loads(message)

        if type(msg) is not dict:
            raise Exception("Improper protocol message")
        if "EncryptedTS" not in msg:
                raise Exception("Improper protocol message")
        
        if "AuthNonce" in msg and self._MWait != None and  self._ServerMode:
            # if we both try to secure at the same time, the client gets priority and the server abandons their attempt and responds to the client
            self._MWait = None
            self._DHExponent = None
            self._BootstrapKey = None
            
        if self._MWait == None:
            # other is initiating
            if "AuthNonce" not in msg:
                raise Exception("Improper protocol message")
            AuthNonce = msg["AuthNonce"]
            self.SetBootstrapKey(AuthNonce, secret)
        
        TSBytes = msg["EncryptedTS"] # TODO: @Sanjeev decrypt and throw error if incorrect
        TSSeconds = float(TSBytes.decode())
        TSAge = datetime.today().timestamp() - TSSeconds
        # TODO: @Joshua compare timestamps and throw exception if TS is old

        if self._MWait == None:
            # We are responding to an initation
            # TODO @Brendon generate DH exponent and set session key
            resp = {}
            response = self._ServerInitVal if self._ServerMode else self._ClientInitVal

            timestamp = datetime.today().timestamp()
            ts_bytes = str(timestamp).encode()

            resp["EncryptedTS"] = ts_bytes # TODO: @Sanjeev encrypt with bootstap key
            resp["DiffieHellman"] = [] # TODO: @Brendon add DH part key here

            return response + pickle.dumps(resp)
        else:
            # We are processing a response
            # TODO @Brendon generate set session key with DH exponent we've already set
            pass

        self._DHExponent = None
        self._MWait = None
        return None

    # TODO: @Brendon calculate DH shared secret
    def SetSessionKey(self, OtherPublicDH):
        """
        Setting the key for the current session
        
        Parameters:
        OtherPublicDH: g^a mod p from the other party for diffie hellman

        Raises:
        Exception: if self._DHExponent == None
        """
        self._SessionKey = b'PASSWORD' # use g^a mod p and our DH exponent to calculate session key
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
