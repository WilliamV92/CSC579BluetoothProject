from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from Crypto import Random
from Crypto.PublicKey import RSA

'''
Methods for Symmetric Encryption with AES in CBC Mode, including helper methods
for adding and removing padding.
'''
# returns cipher text for the given plaintext, encrypted with AES in CBC mode.
# the iv is prepended to the cipher text when returned, so it can be used by decryption method.
# this method will pad the plaintext to the appropriate block size.
def encrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(AES.block_size, plaintext)
    print(b"padded plaintext+digest: " + padded)
    cipher_text = cipher.encrypt(padded)
    return iv + cipher_text


# decrypts the specified cipher text with AES in CBC mode.
# the method assumes the cipher text is prepended with the iv used during encryption.
# after cipher text is decrypted, padding is removed from the resulting plaintext.
def decrypt(block_size, key, ciphertext):
    iv = ciphertext[0:block_size]
    print("iv:")
    print(iv)
    ciphertext = ciphertext[block_size:]
    print(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    unpadded = unpad(plaintext)
    return unpadded

def generateAesIv():
    return Random.new().read(AES.block_size)


# this method pads the data with One and Zeroes style padding
def pad(blocksize, text):
    remainder = len(text) % blocksize
    if remainder == 0:
        # no padding necessary
        return text
    length = blocksize - remainder
    padding = b'\x80'
    for i in range(length - 1):
        padding = padding + b"\x00"
    print("pad: ")
    print(padding)
    return text + padding

# returns data with Ones and Zeroes padding removed
def unpad(padded_text):
    padded_text = padded_text.rstrip(b'\x00')
    if padded_text[len(padded_text) - 1:] == b'\x80':
        return padded_text[:-1]
    else:
        return padded_text

def generateSessionKey(key_size):
    return Random.new().read(key_size)

'''
Unused padding methods. These methods pad to block size with random bytes.
Not using this for now, because the peer needs to know length of padding
when unpacking the message.

# pads text so that it is a multiple of blocksize. if text is already a multiple of blocksize,
# a full block of padding is added.
def pad(blocksize, text):
    length = blocksize - (len(text) % blocksize)
    pad_bytes = Random.new().read(length)
    print(b"pad: " + pad_bytes)
    return text + pad_bytes


# returns text with padding removed
def unpad(original_len, padded_text):
    return padded_text[0:original_len]
'''

'''
Messages for generating a hash digest and verifying data integrity
'''
# returns a digest of given text using SHA-256
def sha256Hash(text):
    h = SHA256.new()
    h.update(text)
    print("Digest: ")
    print(h.digest())
    return h.digest()

# appends a digest to specified text and returns it
def appendSha256Digest(text):
    digest = sha256Hash(text)
    return text + digest

# removes 32-byte (256 bit) digest from text and returns original text and digest
def removeSha256Digest(text):
    text_len = len(text) - 32
    digest = text[text_len:]
    text = text[0:text_len]
    return text, digest

# given data with a digest, this method will remove the digest, recalculate the digest for the original data,
# and compare the recalculated and original digests. True is returned if the Hashes are the same.
def verifyIntegrity(data):
    text, digest = removeSha256Digest(data)
    recalculated_digest = sha256Hash(text)
    print("new hash: ")
    print(recalculated_digest)
    is_valid = True if digest == recalculated_digest else False
    return is_valid

def generatePersistenceKeyFromPassword(password):
    # take SHA-1 hash of password - 160 bit digest
    sha_hash = SHA.new()
    sha_hash.update(b'Hello')
    initial_digest = sha_hash.digest()
    # take sha-256 hash of initial digest
    return sha256Hash(initial_digest)

'''
Complex utility methods that combine encryption and data integrity operations
'''
# Hashes the provided plaintext and encrypts the plaintext with appended digest
# with AES in CBC mode. Returns cipher text
def encryptAndHash(key, iv, plaintext):
    plaintext = appendSha256Digest(plaintext)
    print(b"plaintext + digest: " + plaintext)
    ciphertext = encrypt(key, iv, plaintext)
    return ciphertext

def decryptAndVerifyIntegrity(key, ciphertext):
    data = decrypt(AES.block_size, key, ciphertext)
    print(b"decrypted (data + digest): " + data)
    isValid = verifyIntegrity(data)
    print("isValid: {}".format(isValid))
    plaintext = None
    if isValid:
        plaintext, digest = removeSha256Digest(data)
    return plaintext


'''
Methods involving public key encryption with RSA
'''
def generateRsaPublicKeyPair():
    rsa_key_pair = RSA.generate(2048)
    return rsa_key_pair

def getPublicKeyToExport(rsa_key_pair):
    public_key = rsa_key_pair.publickey().exportKey('DER')
    return public_key

def importPublicKey(public_key):
    rsa_public_key = RSA.importKey(public_key)
    return rsa_public_key

def rsa_sign(rsa_key, data):
    hash = SHA.new(data)
    signer = PKCS1_v1_5.new(rsa_key)
    signature = signer.sign(hash)
    return signature

def rsa_verify_signature(rsa_public_key, data, signature):
    verified = False
    h = SHA.new(data)
    verifier = PKCS1_v1_5.new(rsa_public_key)
    if verifier.verify(h, signature):
        verified = True
        print("The signature is authentic.")
    else:
        print("The signature is not authentic.")
    return verified

def rsa_encrypt(rsa_public_key, plaintext):
    return rsa_public_key.encrypt(plaintext, 32)[0]

def rsa_decrypt(rsa_key, ciphertext):
    return rsa_key.decrypt(ciphertext)


'''
def main():

    # this sample works for reading a file, encrypting an image file, saving an encrypted file, reading it back in,
    # decrypting the data, then saving the file under a new name.
    user_password = "userpassword"
    persistence_key = generatePersistenceKeyFromPassword(user_password)
    iv = generateAesIv()

    file_to_send = open("car.png", 'rb')
    file_data = file_to_send.read()
    file_cipher = encryptAndHash(persistence_key, iv, file_data)

    cipher_file = open("cipherFile", 'wb')
    cipher_file.write(file_cipher)
    cipher_file.close()

    read_cipher_file = open("cipherFile", 'rb')
    encrypted_file_data = read_cipher_file.read()
    cipher_file.close()

    decrypted_file = decryptAndVerifyIntegrity(persistence_key, encrypted_file_data)
    local_file = open("carTest.png", 'wb')
    local_file.write(decrypted_file)
    local_file.close()

# Test code for RSA public key functions
    rsa_key_pair = generateRsaPublicKeyPair()
    public_key = getPublicKeyToExport(rsa_key_pair)
    print("public key original: ")
    print(public_key)
    imported_pk = importPublicKey(public_key)
    print("public key import test: ")
    print(imported_pk.exportKey('DER'))
    print("32byte key:")
    session_key = Random.new().read(32)
    print(session_key)
    ciphertext = rsa_encrypt(imported_pk, session_key)
    print("session key encrypted with public key: ")
    print(ciphertext)
    plaintext = rsa_decrypt(rsa_key_pair, ciphertext)
    print("plaintext: ")
    print(plaintext)
    print("Sign 32byte session key with Private Key:")
    signature = rsa_sign(rsa_key_pair, session_key)
    print(signature)
    rsa_verify_signature(imported_pk, session_key, signature)
    print("sign encrypted: ")
    sig_cipher = rsa_encrypt(imported_pk, signature)
    print(sig_cipher)
    sig_plain = rsa_decrypt(rsa_key_pair, sig_cipher)
    print("sign plain again: ")
    print(sig_plain)
    print(len(sig_plain))

# Test code for symmetric encryption and hash functions.
    key = b'Sixteen byte key'
    print("iv:")
    iv = generateAesIv()
    print(iv)
    plaintext = b'01234567890012345'
    print("plaintext: ")
    print(plaintext)

    cipher_text = encryptAndHash(key, iv, plaintext)
    print("ciphertext (iv + {text + hash} + padding: ")
    print(cipher_text)

    decrypted_text = decryptAndVerifyIntegrity(key, cipher_text)
    print("decrypted text: ")
    print(decrypted_text)
    print(decrypted_text.decode())


main()
'''