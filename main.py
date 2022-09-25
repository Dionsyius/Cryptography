
# RSA is a public-key encryption algorithm that uses an asymmetric encryption algorithm to encrypt data #
#RSA is a type of asymmetric encryption, which uses two different but linked keys.
# In RSA cryptography, both the public and the private keys can encrypt a message.
# The opposite key from the one used to encrypt a message is used to decrypt it.#
import rsa


def generate_keys():
    (public_key, private_key) = rsa.newkeys(1024)
    with open('keys/public_key.pem', 'wb') as f:
        f.write(public_key.save_pkcs1('PEM'))

    with open('keys/private_key.pem', 'wb') as f:
        f.write(private_key.save_pkcs1('PEM'))

def load_keys():
    with open('keys/public_key.pem', 'rb') as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())


    with open('keys/private_key.pem', 'rb') as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    return public_key , private_key

def encrypt(msg, key):
    return rsa.encrypt(msg.encode('ascii'), key)

def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except :
        return False

def sign_sha1(msg, key):
    return rsa.sign(msg.encode('ascii'), key, 'SHA-1')

def verify_sha1(msg, signature, key):
    try:
        return rsa.verify(msg.encode('ascii'), signature, key) == 'SHA-1'
    except :
        return False


generate_keys()
pub_key, private_key = load_keys()
print(pub_key)
print(private_key)


message = input('Enter your Secret Message: ')
ciphertext = encrypt(message, pub_key)
print(ciphertext)

signature = sign_sha1(message, private_key)
print(signature)

plaintext = decrypt(ciphertext, private_key)
print(plaintext)