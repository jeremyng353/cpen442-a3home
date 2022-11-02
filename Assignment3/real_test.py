from protocol import Protocol
import os
# g=3, p=5, K=os.urandom(16) 
K = os.urandom(16)
protClient = Protocol("Client", K, 3, 5)
protServer = Protocol("Server", K, 3, 5)
init_msg = protClient.GetProtocolInitiationMessage()
print(f"Initial message = {init_msg}")
check = protClient.IsMessagePartOfProtocol(init_msg)
print(f"check initial message = {check}")
msg_2 = protServer.ProcessReceivedProtocolMessage(init_msg)
print(f"Message 2 = {msg_2}")
msg_3 = protClient.ProcessReceivedProtocolMessage(msg_2)
print(f"Message 3 = {msg_3}\n")
msg_4 = protServer.ProcessReceivedProtocolMessage(msg_3)
print(f"Message 4 = {msg_4}\n")
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