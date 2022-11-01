from protocol import Protocol
import os
import base64 as b64
test = Protocol("Alice", os.urandom(16), 7, 15)
plaintext = "this lab kinda rough bro"
print(test.DecryptAndVerifyMessage(test.EncryptAndProtectMessage(plaintext)))
# print(b64.decodebytes(test.EncryptAndProtectMessage(plaintext)))
# bytetext = None
# print(b64.decode(test.EncryptAndProtectMessage(plaintext), bytetext))

# print(test.DecryptAndVerifyMessage(test.EncryptAndProtectMessage(plaintext)))


# test.SetSessionKey(os.urandom(16))
# “App”, Ra, 1 
# test.ProcessReceivedProtocolMessage(["App", 28, 1])

# Rb, {“Server”, Ra, ga mod p}K_as, 2
# test.ProcessReceivedProtocolMessage([13, test.EncryptAndProtectMessage("Server, 28, 12"), 2])
# test.ProcessReceivedProtocolMessage(f"22, {test.EncryptAndProtectMessage('Server, 14, 4')}, 2")

# {“App”, Rb, gs mod p}K_as, 3
# test.ProcessReceivedProtocolMessage([test.EncryptAndProtectMessage("App, 3, 14"), 3])
# test.ProcessReceivedProtocolMessage(f"{test.EncryptAndProtectMessage('App, 22, 13')}, 3")


# ct = test.EncryptAndProtectMessage("9074326902mviofsafmjsaidfj0aea9wrim0vimfkmlcs")
# print(ct)
# print(test.DecryptAndVerifyMessage(ct))