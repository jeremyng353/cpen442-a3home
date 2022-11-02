import os
import secrets
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
import base64 as b64
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
        self._messageCounter = 1
        self._myNonce = None
        self._otherNonce = None
        self._myName = name
        self._otherName = None
        self._myExponent = 3 # currently using 3 for testing, replace with secrets.randbits(8)
        self._myDH = (self._g ** self._myExponent) % self._p
        self._otherDH = None
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    def GetProtocolInitiationMessage(self):
        # Send Message: "my_name", my_nonce, 1
        nonce = secrets.randbits(32)
        self._myNonce = nonce    
        self._messageCounter = 2
        return [self._myName, self._myNonce, 1]
        # return f"{self._myName}, {self._myNonce}, 1"


    # Checking if a received message is part of your protocol (called from app.py)
    def IsMessagePartOfProtocol(self, message):
        # check message_counter
        # return message[-1] == self._messageCounter
        return self._messageCounter <= 3


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        # TODO: IMPORTANT, app.py calls this function with a string as the input
        print("processreceived called")
        match self._messageCounter: # message counter      
            case 1:
                # Received: [“other_name”, other_nonce, 1] 
                self._otherName = message[0]
                self._otherNonce = message[1]
                print("\n PROCESSING HANDSHAKE MSG 1 \n")
                print(f"Other name = {self._otherName}")
                print(f"Other nonce = {self._otherNonce}")

                # send next msg, increment message_counter
                self._myNonce = secrets.randbits(32)
                print(f"My nonce generated = {self._myNonce}")
                # my_nonce, E("my_name", other_nonce, myDH, K), 2
                next_message = [self._myNonce, self.EncryptAndProtectMessage(f'{self._myName}, {self._otherNonce}, {self._myDH}'), 2]
                # next_message = f"{self._myNonce}, {self.EncryptAndProtectMessage(f'{self._myName}, {self._otherNonce}, {self._myDH}')}, 2"
                self._messageCounter = 3
                print(str(next_message))
                return next_message
                
            case 2: # counter = 2
                ## Received: other_nonce, E("other_name", my_nonce, otherDH, K), 2
                self._otherNonce = message[0]
                cipher_text = message[1]
                print("\n PROCESSING HANDSHAKE MSG 2 \n")
                    
                '''
                    TODO
                    there's something wrong with message[1], i think its due to message being a string instead of being bytes
                    however, aren't messages technically sent as a bitstream anyways
                '''  
                plaintext = self.DecryptAndVerifyMessage(cipher_text).split(", ")
                self._otherName = plaintext[0]
                my_nonce = int(plaintext[1])
                self._otherDH = int(plaintext[2])

                print(f"other name = {self._otherName}")
                print(f"My nonce, according to received message = {my_nonce}")
                print(f"My actual nonce = {self._myNonce}")
                print(f"Other nonce = {self._otherNonce}")
                print(f"other DH = {self._otherDH}")

                #assert(my_nonce == self._myNonce)

                # TODO: encryptandprotectmessage is currently byte-like, not string
                # Send E(“my_name”, other_nonce, my_DH, K), 3
                next_message = [self.EncryptAndProtectMessage(f'{self._myName}, {self._otherNonce}, {self._myDH}'), 3]
                # next_message = f"{self.EncryptAndProtectMessage(f'{self._myName}, {self._otherNonce}, {self._myDH}')}, 3"

                self.SetSessionKey()
                self._messageCounter = 4
                print(str(next_message))
                return next_message
                
            case 3:
                # Received : E(“other_name”, my_nonce, other_DH, K), 3
                print("\n PROCESSING HANDSHAKE MSG 3 \n")
                plaintext = self.DecryptAndVerifyMessage(message[0]).split(", ")
                print(f"plaintext: {plaintext}")
                other_name = plaintext[0]
                my_nonce = int(plaintext[1])
                self._otherDH = int(plaintext[2])

                print(f"Other name recieved in encrypted message = {other_name}")
                print(f"actual other name = {self._otherName}")
                print(f"my nonce recieved in encrypted message= {my_nonce}")
                print(f"my actual nonce = {self._myNonce}")
                print(f"other DH = {self._otherDH}")

                #assert(other_name == self._otherName)
                #assert(my_nonce == self._myNonce)

                self.SetSessionKey()
                # TODO confirm behavior after connection established
                # TODO: not sure if messageCounter should be reset to 1 or another number to indicate we're sending data now
                self._messageCounter = 4       
                # TODO: send message with DH key  
                next_message = "encrypted data"
                return next_message
            
            case 4:
                # IMPORTANT: treat message as str here?
                return self.DecryptAndVerifyMessage(message)
            
            case _:
                # TODO: throw an exception, message is not part of protocol
                pass


    # Setting the key for the current session
    def SetSessionKey(self):
        self._sessionKey = (self._otherDH ** self._myExponent) % self._p
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERIFICATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plaintext):
        # TODO: use key as key can be DH, shared secret symmetric_key
        iv = os.urandom(16)      
        encrypted = self._Encrypt(plaintext, self._symmetricKey, iv)
        print(f"type of the encrypted message = {type(encrypted)}")
        print(f'length of encrypted: {len(encrypted)}')
        print(f'length of str(encrypted): {len(str(encrypted))}')
        print(f'len of bytes(str(encrypted)): {len(bytes(str(encrypted), "utf-8"))}')
        return encrypted

    # Decrypting and verifying messages, specifically for processing 2nd and 3rd messages in handshake.
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERIFICATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, ciphertext):
        # TODO: use key because it can be DH, symmetric_key
        print(f'type of ciphertext before parsing: {type(ciphertext)}')
        print(f'len of ciphertext before parsing: {len(ciphertext)}')
        
        iv = ciphertext[:16]
        tag = ciphertext[-16:]
        print("-------------------------")
        print(ciphertext)
        print(iv)
        print("-------------------------")
        print("-------------------------")
        print(len(ciphertext))
        print(len(iv))
        print(type(iv))
        print(len(tag))
        print(len(ciphertext[16:len(ciphertext)-16]))
        print("-------------------------")
        decryptor = Cipher(algorithms.AES(self._symmetricKey), modes.CBC(iv)).decryptor()
        print('line 171')
        
        plaintext = decryptor.update(ciphertext[16:len(ciphertext)-16]) + decryptor.finalize()
        # plaintext = plaintext.decode('utf-8').strip('0')
        print("------p==------")
        print(plaintext)
        plaintext = plaintext.decode('utf-8').strip('0')
        print("PLAINTEXT")
        print(plaintext)
        print("ENDPLAINTEXT")
        
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
        print(type(plaintext))
        padded_data = bytes(plaintext, 'utf-8') + (16 - len(bytes(plaintext, 'utf-8')) % 16) * b'0'
        
        # append iv: https://stackoverflow.com/questions/44217923/how-does-aes-decrypt-with-a-different-iv
        # TODO: needs to return as a string
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        print(ciphertext)
        
        return ciphertext
        # return iv + encryptor.update(padded_data) + encryptor.finalize()


# Main logic
if __name__ == '__main__':
    # g=3, p=5, K=os.urandom(16) 
    prot = Protocol("Client", os.urandom(16), 3, 5)
    init_msg = prot.GetProtocolInitiationMessage()
    print(f"Initial message = {init_msg}")
    check = prot.IsMessagePartOfProtocol(init_msg)
    print(f"check initial message = {check}")
    msg_2 = prot.ProcessReceivedProtocolMessage(init_msg)
    print(f"Message 2 = {msg_2}")
    msg_3 = prot.ProcessReceivedProtocolMessage(msg_2)
    print(f"Message 3 = {msg_3}\n")
    #TODO test with two instances of the program running

