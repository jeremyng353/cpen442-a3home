from protocol import Protocol
import os

test = Protocol()
test.SetSessionKey(os.urandom(16))
ct = test.EncryptAndProtectMessage("9074326902mviofsafmjsaidfj0aea9wrim0vimfkmlcs")
print(test.DecryptAndVerifyMessage(ct))