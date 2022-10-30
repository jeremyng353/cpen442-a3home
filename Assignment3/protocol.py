import os
import secrets
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding

# from Assignment3.test import DecryptAndVerifyMessage

class Protocol:
    # Initializer (Called from app.py)
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
    def GetProtocolInitiationMessage(self):
        # Message: "App", Ra, 1
        nonce = secrets.randbits(32)
        self._nonceA = nonce    
        self._message_counter = 1
        return f"{self._myName}, {self._nonceA}, 1"


    # Checking if a received message is part of your protocol (called from app.py)
    def IsMessagePartOfProtocol(self, message):
        #check message_counter
        return int(message.split(", ")[2]) == self._message_counter


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        args = message.split(", ")
        match args[-1]: # message counter      
            case "1":
                # “App”, Ra, 1 
                self._otherName = args[0]
                self._nonceA = args[1]
                print("\n CASE 1 in PROCESS \n")
                print(f"Other name: {self._otherName}")
                print(f"Ra = {self._nonceA}")

                # send next msg, increment message_counter
                self._nonceB = secrets.randbits(32)
                print(f"Generate Rb = {self._nonceB}")
                # Rb, E("Sever", Ra, ga mod p, K), 2
                next_message = f"{self._nonceB}, {self.EncryptAndProtectMessage(f'{self._myName}, {self._nonceA}, {self._myDH}', self._symmetricKey)}, 2"
                self._message_counter = 2
                return next_message
                
            case "2": # counter = 2
                ## Rb, E("Sever", Ra, ga mod p, K), 2
                Rb = args[0]
                cipher_text = args[1]
                print("\n CASE 2 in PROCESS \n")
                    
                '''
                    TODO
                    there's something wrong with args[1], i think its due to message being a string instead of being bytes
                    however, aren't messages technically sent as a bitstream anyways
                '''  
                plaintext = self.DecryptAndVerifyMessage(cipher_text, self._symmetricKey)
                other_mode = plaintext[0]
                Ra = plaintext[1]
                ga_mod_p = plaintext[2]

                print(f"Rb = {Rb}")
                print(f"other name = {other_mode}")
                print(f"Ra = {Ra}")
                print(f"g_a mod p = {ga_mod_p}")

                #assert(Ra == self._nonceA)

                # TODO: encryptandprotectmessage is currently byte-like, not string
                # E(“App”, Rb, gb mod p, K), 3
                next_message = f"{self.EncryptAndProtectMessage(f'{self._myName}, {self._nonceB}, {self._gb_modp}', self._symmetricKey)}, 3"

                self._otherDH = ga_mod_p
                self._otherDH = 4
                self.SetSessionKey()

                self._message_counter = 3
                return next_message
                
            case "3":
                # E(“App”, Rb, gb mod p, K), 3
                plaintext = self.DecryptAndVerifyMessage(args[0], self._symmetricKey)
                other_mode = plaintext[0]
                Rb = plaintext[1]
                gb_mod_p = plaintext[2]

                print(f"other name = {other_mode}")
                print(f"Rb = {Rb}")
                print(f"g_b mod p = {gb_mod_p}")

                #assert(other_mode == self._otherName)
                #assert(Rb == self._nonceB)
                    
                self._gb_modp = gb_mod_p

                self.SetSessionKey()
                self._message_counter = 1       
                #TODO: send message  with DH key  
                next_message = "encrypted data"
                return next_message
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
    def EncryptAndProtectMessage(self, plaintext, key):
        # TODO: use key as key can be DH, shared secret symmetric_key
        iv = os.urandom(16)      
        return self._Encrypt(plaintext, self._symmetricKey, iv)


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERIFICATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, ciphertext, key):
        # TODO: use key because it can be DH, symmetric_key
        return ["Server", "Ra", "g_a mod p"]
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
        return "Cipher text"
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


# Main logic
if __name__ == '__main__':
    # g=3, p=5, K=10 
    prot = Protocol("Client", 10, 3, 5)
    init_msg = prot.GetProtocolInitiationMessage()
    print(f"Initial message = {init_msg}")
    check = prot.IsMessagePartOfProtocol(init_msg)
    print(f"check initial message = {check}")
    msg_2 = prot.ProcessReceivedProtocolMessage(init_msg)
    print(f"Message 2 = {msg_2}")
    msg_3 = prot.ProcessReceivedProtocolMessage(msg_2)
    print(f"Message 3 = {msg_3}\n")
    #TODO test with two instances of the program running

