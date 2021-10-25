import json
from elliptic_curve_diffie_hellman import *
from cipher import *
from enum import IntEnum
from random import randrange
import sys

class User(IntEnum):
    CLIENT = 0
    SERVER = 1
class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self.ecdh = ECDH()
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, id):
        self._my_nounce = randrange(sys.maxsize)
        msg = {
            'id': id,
            'authenticate_status': 0,
            'nounce': self._my_nounce

        }
        return json.dumps(msg)


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        try:
            # plaintext = self.DecryptAndVerifyMessage(message)
            msg = json.loads(message)
            return isinstance(msg, dict) and "authenticate_status" in msg
        except json.decoder.JSONDecodeError:
            return False


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message, id):
   
        msg = json.loads(message)
        previous_step = msg['authenticate_status']

        shared_key = ''
        return_message = ''
        if previous_step == 0:
            self._other_nounce = msg['nounce']
            self._my_nounce = randrange(sys.maxsize)
            message_to_encrypt = {
               'id': id,
               'your_nounce': self._other_nounce,
               'public_key': str(self.ecdh.get_public_key()),
            }

            return_message = json.dumps({
                'authenticate_status': 1,
                'nounce': self._my_nounce,
                'encrypted_message': str(self.EncryptAndProtectMessage(json.dumps(message_to_encrypt)))
            })

        elif previous_step == 1:
            self._other_nounce = msg['nounce']
            encrypted_message = msg['encrypted_message']
            decrypted_message = json.loads(self.DecryptAndVerifyMessage(encrypted_message))
            decrypted_nounce = decrypted_message['your_nounce']
            other_id = decrypted_message['id']

            # Verify the other side by checking returned nounce
            if (self._my_nounce != decrypted_nounce):
                raise Exception('Authentication failed veryfying nounce after step 1')

            # Verify the other side by checking identity
            if (id == User.SERVER and other_id != User.CLIENT or id == User.CLIENT and other_id != User.SERVER):
                raise Exception('Authentication failed veryfying identity after step 1')

            print('1-way Authentication successed')
            other_public_key = decrypted_message['public_key']
            shared_key = self.ecdh.get_shared_key(other_public_key)

            # Passed 1 way authentication here
            message_to_encrypt = {
               'id': id,
               'your_nounce': self._other_nounce,
               'public_key': str(self.ecdh.get_public_key()),
            }

            # Verify the other side by checking identity
            return_message = json.dumps({
                'authenticate_status': 2,
                'encrypted_message': str(self.EncryptAndProtectMessage(json.dumps(message_to_encrypt)))
            })
            
        elif previous_step == 2:
            encrypted_message = msg['encrypted_message']
            decrypted_message = json.loads(self.DecryptAndVerifyMessage(encrypted_message))
            decrypted_nounce = decrypted_message['your_nounce']
            other_id = decrypted_message['id']

            # Verify the other side by checking returned nounce
            if (self._my_nounce != decrypted_nounce):
                raise Exception('Authentication failed veryfying nounce at step 2')
            
            if (id == User.SERVER and other_id != User.CLIENT or id == User.CLIENT and other_id != User.SERVER):
                raise Exception('Authentication failed veryfying identity after step 2')

            print('Mutual Authentication successed')
            # Passed mutual authentication here
            other_public_key = decrypted_message['public_key']
            shared_key = self.ecdh.get_shared_key(other_public_key)
            
        else:
            raise Exception('Authentication failed!')
        
        
        return shared_key, return_message

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
