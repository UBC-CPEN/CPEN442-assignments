class Protocol:
    Verbose = True

    INIT = "init"
    WAIT_FOR_CLIENT = "waitForClient"
    WAIT_FOR_SERVER = "waitForServer"
    ESTABLISHED = "established"

    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        self.state = self.INIT
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        # "I'm Alice" + Ra
        # (Init) -> Waiting for server message
        self._setStateTo(self.WAIT_FOR_SERVER)
        return ""


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return False


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        # <ID>,<Rc>          MSG_TYPE:INIT       (Init) -> Waiting for client message
        # <Es>,<Hs>,<Rs>     MSG_TYPE:AUTH       (Client: Waiting for server message) -> Established
        # <Ec>,<Hc>,<Rc>     MSG_TYPE:AUTH       (Server: Waiting for client message) - > Established


        msg_type = self._getMessageType(message)

        if msg_type == "INIT_MSG":
            if self.state != self.INIT:
                # return error and reset state to INIT
                self._setStateTo(self.INIT)
                return

            self._setStateTo(self.WAIT_FOR_CLIENT)

        elif msg_type == "AUTH_MSG":
            if self._verifyMessageAuth(message):
                if self.state != self.WAIT_FOR_CLIENT or self.state != self.WAIT_FOR_SERVER:
                    # return error and reset state to INIT
                    self._setStateTo(self.INIT)

                self._setStateTo(self.ESTABLISHED)

        pass

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text

    def _setStateTo(self, next_state):
        if self.Verbose:
            print(self.state + " --> " + next_state)

        self.state = next_state

    def _getMessageType(self, message):
        # parse message and determine type: INIT_MSG or AUTH_MSG
        return "INIT_MSG"

    def _verifyMessageAuth(self, message):
        # Decrypt and compare hashes
        return True