from protocol import Protocol
import os

test = Protocol("Alice", os.urandom(16), 7, 15)
# test.SetSessionKey(os.urandom(16))
# “App”, Ra, 1 
test.ProcessReceivedProtocolMessage("App, 14, 1")

# Rb, {“Server”, Ra, ga mod p}K_as, 2
test.ProcessReceivedProtocolMessage(f"22, {test.EncryptAndProtectMessage('Server, 14, 4')}, 2")

# {“App”, Rb, gs mod p}K_as, 3
test.ProcessReceivedProtocolMessage(f"{test.EncryptAndProtectMessage('App, 22, 13')}, 3")


# ct = test.EncryptAndProtectMessage("9074326902mviofsafmjsaidfj0aea9wrim0vimfkmlcs")
# print(ct)
# print(test.DecryptAndVerifyMessage(ct))