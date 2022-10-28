import os
import secrets
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding

# from Assignment3.test import DecryptAndVerifyMessage

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self, name, symmetricKey, g, p):
        self._sessionKey = None
        self._symmetricKey = symmetricKey
        self._fullKey = None
        self._privateKey = None
        self._g = g
        self._p = p
        self._message_counter = 1
        self._nonceA = None
        self._nonceB = None
        self._myName = name
        self._otherName = None
        self._myExponent = 3 # currently using 3 for testing, replace with secrets.randbits(8)
        self._myDH = (self._g ** self. _myExponent) % self._p
        self._otherDH = None
        self._ga_modp = None
        self._gb_modp = None
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        nonce = secrets.randbits(32)
        self._nonceA = nonce    
        self._message_counter = 2
        return f"{self._myName}, {nonce}, 1"


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return message.split(", ")[-1] == self._message_counter


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        args = message.split(", ")
        print(args[-1])
        match args[-1]:              
            case "1":
                # “App”, Ra, 1 
                self._otherName = args[0]
                self._nonceA = args[1]
                
                print(self._otherName)
                print(self._nonceA)
                # TODO: send next msg, increment message_counter
                self._nonceB = secrets.randbits(32)
                # TODO: encryptandprotectmessage is currently byte-like, not string
                next_message = f"{self._nonceB}, {self.EncryptAndProtectMessage(f'{self._myName}, {self._nonceA}, {self._myDH}')}, 2"
                # TODO: send next_message
                self._message_counter = 2
                
            case "2":
                # Rb, {“Server”, Ra, ga mod p}K_as, 2
                self._nonceB = args[0]
                print(self._nonceB)
                print("line 73")
                for x in args:
                    print(x)
                    
                '''
                    TODO
                    there's something wrong with args[1], i think its due to message being a string instead of being bytes
                    however, aren't messages technically sent as a bitstream anyways
                '''  
                plaintext = self.DecryptAndVerifyMessage(args[1]).split(", ")
                print("line 75")
                print(plaintext)
                print("line 77")
                self._otherName = plaintext[0]
                print(self._otherName)
                # if self._nonceA != plaintext[1]:
                    # TODO: error, encrypted nonceA is not same nonceA in first message

                self._otherDH = plaintext[2]
                print(self._ga_modp)
                
                # TODO: encryptandprotectmessage is currently byte-like, not string
                next_message = f"{self.EncryptAndProtectMessage(f'{self._myName}, {self._nonceB}, {self._gb_modp}')}, 3"
                # TODO: send next_msg
                self.SetSessionKey()
                self._message_counter = 3
                
            case "3":
                # {“App”, Rb, gs mod p}K_as, 3
                plaintext = self.DecryptAndVerifyMessage(args[1]).split(", ")
                print(plaintext)
                # if self._otherName != plaintext[0]:
                    # TODO: error, not the same person?
                    
                # if self._nonceB != plaintext[1]:
                    # TODO: error, encrypted nonceB is not same nonceB in second message
                    
                self._gb_modp = plaintext[2]
                print(self._gb_modp)
                self.SetSessionKey()
                
                self._message_counter = 1                    
                
        pass


    # Setting the key for the current session
    # TODO: Diffie Helman - Sam
    def SetSessionKey(self):
        # tmp = partialkey ** self._privateKey
        # self._fullKey = tmp % self._p
        self._sessionKey = (self._otherDH ** self._myExponent) % self._p
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERIFICATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plaintext):
        iv = os.urandom(16)      
        return self._Encrypt(plaintext, self._symmetricKey, iv)


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERIFICATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, ciphertext):
        # ciphertext = str(ciphertext).encode()
        iv = ciphertext[0:16]
        tag = ciphertext[-16:]
        decryptor = Cipher(algorithms.AES(self._symmetricKey), modes.CBC(iv)).decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
        plaintext = plaintext.decode('utf-8')
        
        tag_new = self._Encrypt(plaintext, self._symmetricKey, iv)[-16:]
        if tag != tag_new:
            print(tag)
            print(tag_new)
            print(plaintext)
            return "ERROR: integrity check failed"
        
        try: 
            return plaintext
        except:
            return "ERROR: authentication check failed"

    def _Encrypt(self, plaintext, key, iv):
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(bytes(plaintext, 'utf-8')) + padder.finalize()
        
        # ciphertext is in bytes
        # encryptor.update() returns as bytes
        # encryptor.finalize() returns the results of processing the final block as bytes
        # append iv: https://stackoverflow.com/questions/44217923/how-does-aes-decrypt-with-a-different-iv
        # TODO: needs to return as a string
        # retval = iv + encryptor.update(padded_data) + encryptor.finalize()
        # return int.from_bytes(retval, "big")
        return iv + encryptor.update(padded_data) + encryptor.finalize()