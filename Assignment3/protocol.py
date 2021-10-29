from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Hash import SHA3_256
from datetime import datetime
import hashlib
import pickle

class Protocol:
    """
    A class for our encryption protocol.
    ...

    Attributes:
    _SessionKey (bytes):    session key for symmetric encryption
    _BootstrapKey (bytes):  key for encryption of DHE key establishment. based off of shared secret
    _ServerMode (bool):     prototocol mode, server if true, client otherwise
    _DHExponent (int):      our DH exponent. to be 'forgotten' after establishment of session key
    _AuthNonceLen (int):    (CONSTANT) the length of generated nonces in the protocol
    _g (int):               (CONSTANT) our protocol's DH generator
    _p (int):               (CONSTANT) our protocol's DH prime
    _ClientInitVal (bytes): a Sbytes identifying our protocol's initiation message
    _ServerInitVal (bytes): a bytes identifying our protocol's initiation message
    _MWait (datetime):      the time we send our protocol initiation
    """

    def __init__(self):
        """initializes all variables to None"""
        self._SessionKey    = None
        self._BootstrapKey  = None
        self._ServerMode    = True
        self._DHExponent    = None
        self._AuthNonceLen  = 16
        self._AuthNonce     = None
        self._g             = 2
        self._p             = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self._ClientInitVal = b'Client protocol initiation message'
        self._ServerInitVal = b'Server protocol initiation message'
        self._MWait         = None
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

        self._BootstrapKey = bytes([long_key[i] ^ long_key[i+16] for i in range(16)])  # converts 32B hash to 16B key

    def SetClientMode(self):
        """Sets mode to client"""
        self._ServerMode = False
    
    def SetServerMode(self):
        """Sets mode to server"""
        self._ServerMode = True
        
    def GenerateNonce(self):
        """Generates a cryptographically secure random nonce"""
        return get_random_bytes(self._AuthNonceLen)

    def GetProtocolInitiationMessage(self, secret):
        """Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)"""
        msg = {}
        self._AuthNonce = self.GenerateNonce()

        self.SetBootstrapKey(self._AuthNonce, secret)
        timestamp = datetime.today().timestamp()
        ts_bytes = str(timestamp).encode()

        msg["EncryptedTS"] = ts_bytes

        self._DHExponent = randint(999, 16384) # generate a random exponent b for g^b mod p
        msg["DiffieHellman"] = ( pow(self._g , self._DHExponent) % self._p ) #generate the DH part key

        self._MWait = datetime.now()

        # Encrypting the message
        return self.EncryptAndProtectProtocol(pickle.dumps(msg))

    def IsMessagePartOfProtocol(self, message):
        """Checking if a received message is part of your protocol (called from app.py)"""
        if self._BootstrapKey == None or self._SessionKey == None:
            return True
        return False

    def ProcessReceivedProtocolMessage(self, message, secret):
        """
        Processing protocol message

        Raises:
        Exception: if authentication fails
        """
        # Decrypting the message
        message = self.DecryptAndVerifyProtocol(message, secret)
        msg = pickle.loads(message)
        
        if type(msg) is not dict:
            raise Exception("Improper protocol message")
        if "EncryptedTS" not in msg:
            raise Exception("Improper protocol message")
        
        if "AuthNonce" in msg and self._MWait != None and  self._ServerMode:
            # if we both try to secure at the same time, 
            # the client gets priority and the server abandons their attempt and responds to the client
            self._MWait = None
            self._DHExponent = None
            self._BootstrapKey = None
        
        TSBytes = msg["EncryptedTS"]
        TSSeconds = float(TSBytes.decode())
        TSAge = datetime.today().timestamp() - TSSeconds
        # TODO: @Joshua compare timestamps and throw exception if TS is old

        if self._MWait == None:
            # We are responding to an initation
            resp = {}

            timestamp = datetime.today().timestamp()
            ts_bytes = str(timestamp).encode()

            resp["EncryptedTS"] = ts_bytes

            self._DHExponent = randint(999, 16384) # generate a random exponent b for g^b mod p
            resp["DiffieHellman"] = ( pow(self._g , self._DHExponent) % self._p ) #generate the DH part key
            self.SetSessionKey(msg["DiffieHellman"])


            return self.EncryptAndProtectProtocol(pickle.dumps(resp))
        else:
            # We are processing a response
            self.SetSessionKey(msg["DiffieHellman"]) # For now put 1, still waiting for the decryption implmentation, so i can get the DH part key from the received message.

        self._DHExponent = None
        self._MWait = None
        return None

    def SetSessionKey(self, OtherPublicDH):
        """
        Setting the key for the current session
        
        Parameters:
        OtherPublicDH: g^a mod p from the other party for diffie hellman

        Raises:
        Exception: if self._DHExponent == None
        """
        if  OtherPublicDH == None:
                raise Exception("Did not get a valid DH partcial key from other side.")

        if  self._DHExponent == None: 
                raise Exception("The DH Exponent is not set yet.")

        sessionkey = ((pow( OtherPublicDH, self._DHExponent)) % self._p)  
        sessionkey_256b = hashlib.shake_256(
            bytes(str(sessionkey), encoding='utf-8')).hexdigest(8)
        self._SessionKey = bytes(sessionkey_256b, 'utf-8')
        # self._BootstrapKey = None # no longer need this key
        # self._DHExponent = None  # need to forget this exponent
        #pass  #may delete later

    def EncryptAndProtectMessage(self, plain_text):
        """
        Encrypting messages and tag
        RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
        """
        if(self._SessionKey == None):
            return plain_text
        cipher = AES.new(self._SessionKey, AES.MODE_EAX)
        nonce = cipher.nonce
        cipher_text, tag = cipher.encrypt_and_digest(
            plain_text.encode('ascii'))
        return pickle.dumps((nonce, cipher_text, tag))

    def DecryptAndVerifyMessage(self, cipher_text):
        """
        Decrypting and verifying messages
        RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
        """
        if(self._SessionKey == None):
            return cipher_text
        nonce, cipher_text, tag = pickle.loads(cipher_text)
        cipher = AES.new(self._SessionKey, AES.MODE_EAX, nonce=nonce)
        plain_text = cipher.decrypt_and_verify(cipher_text, tag)
        return plain_text.decode('ascii') 

    def EncryptAndProtectProtocol(self, plain_text):
        """
        Encrypting the protocol
        """
        cipher = AES.new(self._BootstrapKey, AES.MODE_EAX)
        nonce = cipher.nonce
        cipher_text, tag = cipher.encrypt_and_digest(plain_text)
        return pickle.dumps((nonce, cipher_text, tag, self._AuthNonce))

    def DecryptAndVerifyProtocol(self, cipher_text, secret):
        """
        Decrypting and verifying the protocol
        """
        nonce, cipher_text, tag, self._AuthNonce = pickle.loads(cipher_text)
        self.SetBootstrapKey(self._AuthNonce, secret)
        cipher = AES.new(self._BootstrapKey, AES.MODE_EAX, nonce=nonce)
        plain_text = cipher.decrypt_and_verify(cipher_text, tag)
        return plain_text
