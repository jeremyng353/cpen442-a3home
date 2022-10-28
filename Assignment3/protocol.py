import os
import secrets
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        pass


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self, name):
        nonce = secrets.randbits(32)
        return f"{name}, {nonce}"


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return False


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        pass


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERIFICATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plaintext):
        iv = os.urandom(16)      
        return self._Encrypt(plaintext, self._key, iv)


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERIFICATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, ciphertext):
        iv = ciphertext[0:16]
        tag = ciphertext[-16:]
        decryptor = Cipher(algorithms.AES(self._key), modes.CBC(iv)).decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
        plaintext = plaintext.decode('utf-8')
        
        tag_new = self._Encrypt(plaintext, self._key, iv)[-16:]
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
        return iv + encryptor.update(padded_data) + encryptor.finalize()