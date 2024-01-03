from Crypto.PublicKey import RSA

keypair = RSA.generate(1024)

public_key = keypair.public_key()

with open('public.pem',"wb") as file:
    file.write(public_key.exportKey('PEM'))
    file.close()

with open('private.pem',"wb") as file:
    file.write(keypair.exportKey('PEM'))
    file.close()