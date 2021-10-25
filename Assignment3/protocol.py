import json
from elliptic_curve_diffie_hellman import *
from cipher import *

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self.ecdh = ECDH()
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, status = "start"):
        msg = {
            "status": status, 
            "encrypted_public_key": self.EncryptAndProtectMessage(str(self.ecdh.get_public_key()))
        }
        return json.dumps(msg)


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        try:
            plaintext = self.DecryptAndVerifyMessage(message)
            msg = json.loads(plaintext)
            return isinstance(msg, dict) and "status" in msg and "encrypted_public_key" in msg
        except json.decoder.JSONDecodeError:
            return False


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        try:
            msg = json.loads(message)
            other_public_key = self.DecryptAndVerifyMessage(str(msg["encrypted_public_key"])).decode("utf-8")
            shared_key = self.ecdh.get_shared_key(other_public_key)

            return_message = self.GetProtocolInitiationMessage("end")
            if msg["status"] == "end":
                return shared_key, ""
            return shared_key, return_message
        except Exception:
            raise Exception('Authentication failed!')


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = str(key)
        print(f"My very secret key is {self._key}")
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        return Cipher.encrypt(plain_text, self._key)


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        return Cipher.decrypt(cipher_text, self._key)
