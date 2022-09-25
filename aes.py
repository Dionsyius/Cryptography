from cryptography.fernet import Fernet

# Symmetric encryption is when a key is used to encrypt and decrypt a message, so whoever encrypted it can decrypt it.
# The only way to decrypt the message is to know what was used to encrypt it; kind of like a password.#
# To use symmetric encryption, we will use the Fernet class which is an implementation of AES

key = Fernet.generate_key()
f = Fernet(key)
token = f.encrypt(b"")
f.decrypt(token)
print(token)
# Your message and bites
msg = "Raphael Obumnaenye Odinamkpa".encode()

# encrypt message
f_obj = Fernet(key)
encrypted_msg = f_obj.encrypt(msg)
print(encrypted_msg)

# final step decrypt the message
decrypted_msg = f_obj.decrypt(encrypted_msg)
print(decrypted_msg)

## We have the key generated
##  Then we have the encrypted message
## and lastly the decrypted message
