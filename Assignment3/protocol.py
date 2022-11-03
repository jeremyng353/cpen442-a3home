import os
import secrets
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
import base64 as b64
from cryptography.hazmat.primitives import padding
import json

class Protocol:
    # Initializer (Called from app.py)
    def __init__(self, name, symmetricKey, g, p):
        self._sessionKey = None
        self._symmetricKey = symmetricKey
        self._g = g
        self._p = p
        self._nextExpectedHandshakeMessage = 1
        self._myNonce = None
        self._otherNonce = None
        self._myName = name
        self._otherName = None
        self._myExponent = secrets.randbits(8)
        self._myDH = (self._g ** self._myExponent) % self._p
        self._otherDH = None
        pass

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    def GetProtocolInitiationMessage(self):
        # Send Message: "my_name", my_nonce, 1
        nonce = secrets.randbits(32)
        self._myNonce = nonce    
        self._nextExpectedHandshakeMessage = 2
        return '{ "name":"' + self._myName + '", "nonce":' + str(self._myNonce) + ', "handshake":' + str(1) +'}'


    # Checking if a received message is part of your protocol (called from app.py)
    def IsMessagePartOfProtocol(self, message):
        try:
            jmessage = json.loads(message)
            return self._nextExpectedHandshakeMessage <= 3 and jmessage["handshake"] == self._nextExpectedHandshakeMessage
        except:
            return False


    # Processing protocol message
    def ProcessReceivedProtocolMessage(self, message):
        jmessage = json.loads(message)
        match jmessage["handshake"]: # message counter      
            case 1:
                # Received: [“other_name”, other_nonce, 1] 
                self._otherName = jmessage["name"]
                self._otherNonce = jmessage["nonce"]
                print("\n PROCESSING HANDSHAKE MSG 1 \n")

                # send next msg, increment message_counter
                self._myNonce = secrets.randbits(32)
                encrypted = self.EncryptAndProtectMessage(f'{self._myName}, {self._otherNonce}, {self._myDH}')
                
                next_message = '{ "nonce":' + str(self._myNonce) + ', "cipher_text":"' + str(b64.b64encode(encrypted).decode()) + '", "handshake":' + str(2) + '}'
                self._nextExpectedHandshakeMessage = 3
                return next_message
                
            case 2: # counter = 2
                # Received: other_nonce, E("other_name", my_nonce, otherDH, K), 2
                self._otherNonce = jmessage["nonce"]
                cipher_text = b64.b64decode(bytes(str(jmessage["cipher_text"]).encode()))
                print("\n PROCESSING HANDSHAKE MSG 2 \n")

                plaintext = self.DecryptAndVerifyMessage(cipher_text)
                plaintext = plaintext.split(", ")
                self._otherName = plaintext[0]
                my_nonce = int(plaintext[1])
                self._otherDH = int(plaintext[2])

                assert my_nonce == self._myNonce
                encrypted = self.EncryptAndProtectMessage(f'{self._myName}, {self._otherNonce}, {self._myDH}')
                next_message = '{ "cipher_text":"' + str(b64.b64encode(encrypted).decode()) + '", "handshake":' + str(3) + '}'

                self.SetSessionKey()
                self._nextExpectedHandshakeMessage = 4
                return next_message
                
            case 3:
                # Received : E(“other_name”, my_nonce, other_DH, K), 3
                cipher_text = b64.b64decode(bytes(str(jmessage["cipher_text"]).encode()))
                print("\n PROCESSING HANDSHAKE MSG 3 \n")
                plaintext = self.DecryptAndVerifyMessage(cipher_text).split(", ")
                other_name = plaintext[0]
                my_nonce = int(plaintext[1])
                self._otherDH = int(plaintext[2])

                assert other_name == self._otherName
                assert my_nonce == self._myNonce

                self.SetSessionKey()
                self._nextExpectedHandshakeMessage = 5       
                next_message = "done"
                return next_message
            
            case _:
                raise Exception("Message is not a part of the handshake protocol.")


    # Setting the key for the current session
    def SetSessionKey(self):
        var = 10221290
        self._sessionKey = var.to_bytes(16, 'big')
        # self._sessionKey = ((self._otherDH ** self._myExponent) % self._p).to_bytes(16, 'big')
        self._myExponent = None
        pass

    # Encrypting messages
    def EncryptAndProtectMessage(self, plaintext):
        iv = os.urandom(16)
        encrypted = None
        if self._sessionKey:
            encrypted = self._Encrypt(plaintext, self._sessionKey, iv)
        else: 
            encrypted = self._Encrypt(plaintext, self._symmetricKey, iv)       
        return encrypted

    # Decrypting and verifying messages, specifically for processing 2nd and 3rd messages in handshake.
    def DecryptAndVerifyMessage(self, ciphertext):
        iv = ciphertext[:16]
        tag = ciphertext[-16:]
        encrypted_text = ciphertext[16:-16]
        decryptor = None
        if self._sessionKey:
            decryptor = Cipher(algorithms.AES(self._sessionKey), modes.CBC(iv)).decryptor()
        else:
            decryptor = Cipher(algorithms.AES(self._symmetricKey), modes.CBC(iv)).decryptor()
        plaintext = decryptor.update(encrypted_text) + decryptor.finalize()
        plaintext = plaintext.decode('utf-8').strip('0')
        
        if tag != encrypted_text[-16:]:
            return "ERROR: integrity check failed"
        
        try: 
            return plaintext
        except:
            return "ERROR: authentication check failed"

    def _Encrypt(self, plaintext, key, iv):
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        padded_data = bytes(plaintext, 'utf-8') + (16 - len(bytes(plaintext, 'utf-8')) % 16) * b'0'
        
        # append iv: https://stackoverflow.com/questions/44217923/how-does-aes-decrypt-with-a-different-iv
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()        
        return iv + ciphertext + ciphertext[-16:]