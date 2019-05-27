import socket
import bluetooth
from protocolConstants import *
from pathlib import Path
import os
from cryptoutil import *

# flag to turn logging on or off
LOGGING_ENABLED = True
# address of remote peer
REMOTE_HOST_ADDRESS = 'localhost'
# port on which remote peer is listening
REMOTE_HOST_PORT = 60001
# master key
MASTER_KEY = b'*%Hah%zgh&hFL#Db'


# helper method for logging. Logging controlled with global flag.
def log(message):
    if LOGGING_ENABLED:
        print(message)

# method for handling secure handshake
def performHandshake(s):
    log("Starting secure handshake...")
    session_key = None

    # send CLIENT HELLO
    message, rsa_key_pair = buildClientHello()
    log("SENDING {}".format(message))
    s.send(message)

    # *** wait for SERVER HELLO ***
    server_public_key = None
    data = s.recv(1024)
    # validate SERVER HELLO
    if data:
        isValid, server_public_key = validateServerHello(data)
        if isValid:
            message, session_key = buildKeyExchange(rsa_key_pair, server_public_key)
            log("SENDING {}".format(message))
            s.send(message)
        else:
            log("Handshake Failed.")
            return False, None
    else:
        log("Handshake Failed.")
        return False, None

    # *** wait for SERVER SESSION BEGIN ***
    data = s.recv(1024)
    # validate SERVER SESSION BEGIN
    if data and validateServerSessionBegin(session_key, data):
        message = buildClientSessionBegin(session_key)
        log("SENDING {}".format(message))
        s.send(message)
    else:
        log("Handshake Failed.")
        return False, None

    # perform client authentication
    if not performClientAuthentication(s, session_key):
        log("Handshake Failed.")
        return False, None

    log("Handshake Successful.")
    return True, session_key

def performClientAuthentication(s, session_key):
    authSuccess = False
    while not authSuccess:
        # get username and password
        username = input("Enter username: ")
        password = input("Enter password: ")
        # build CLIENT AUTH message and send
        message = buildClientAuth(session_key, username, password)
        log("SENDING {}".format(message))
        s.send(message)
        # *** wait for SERVER AUTH REPLY ***
        data = s.recv(1024)
        # validate SERVER AUTH REPLY
        if data:
            reply = validateServerAuthReply(session_key, data)
            if reply == SERVER_AUTH_REPLY_TERMINATE:
                # if max client auth attempts exceeded, server drops connection.
                log("Max client auth attempts exceeded.")
                break
            elif reply == SERVER_AUTH_REPLY_AUTHORIZED:
                log("Client Auth Succesful")
                authSuccess = True
            else:
                log("Client Auth Failed.")
        else:
            break
    return authSuccess

###
# Helper methods for constructing client side protocol handshake messages
###
def buildClientHello():
    message = CLIENT_HELLO.encode()
    # generate rsa public key pair and export public key to share with server
    rsa_key_pair = generateRsaPublicKeyPair()
    exported_public_key = getPublicKeyToExport(rsa_key_pair)
    # build and encrypt message
    message = message + exported_public_key
    iv = generateAesIv()
    message = encryptAndHash(MASTER_KEY, iv, message)
    return message, rsa_key_pair

def buildKeyExchange(rsa_key_pair, server_public_key):
    message = KEY_EXCHANGE.encode()
    # generate 256 bit session key to use for AES
    session_key = generateSessionKey(32)
    print("session key:")
    print(session_key)
    # build 1st segment of message
    message = message + session_key
    # encrypt 1st segment of message with the server's public key
    session_key_message_cipher_text = rsa_encrypt(server_public_key, message)
    # sign session key with client's private key
    signature = rsa_sign(rsa_key_pair, session_key)
    print("session key signature:")
    print(signature)
    # encrypt client signature with the server's public key
    signature_cipher_text = rsa_encrypt(server_public_key, signature)
    complete_message = session_key_message_cipher_text + signature_cipher_text
    # because of security of with RSA encryption, still encrypt this message with master key
    iv = generateAesIv()
    complete_message = encryptAndHash(MASTER_KEY, iv, complete_message)
    return complete_message, session_key

def buildClientSessionBegin(session_key):
    message = CLIENT_SESSION_BEGIN.encode()
    # generate counter, add to message...and encrypt
    iv = generateAesIv()
    message = encryptAndHash(session_key, iv, message)
    return message

def buildClientAuth(session_key, username, password):
    message = CLIENT_AUTH + " " + username + " " + password
    # encrypt
    iv = generateAesIv()
    message = encryptAndHash(session_key, iv, message.encode())
    return message

###
# Helper methods for validating commands in the handshake process on client side.
###

def parseCommandFromPayload(data, expected_command):
    command = data[0:len(expected_command)]
    payload = data[len(expected_command):]
    return command, payload

def validateServerHello(data):
    isValid = False
    server_public_key = None
    log("RECEIVED {}".format(data))
    # decrypt message with mastery key and verify integrity by checking digest
    data = decryptAndVerifyIntegrity(MASTER_KEY, data)
    log("DECRYPTED {}".format(data))
    if data is not None:
        command, payload = parseCommandFromPayload(data, SERVER_HELLO)
        if command.decode() == SERVER_HELLO:
            server_public_key = importPublicKey(payload)
            if server_public_key is not None:
                isValid = True
            else:
                log("Error: Received malformed public key from client.")
        else:
            log("Error: Received unexpected command during handshake.")
    return isValid, server_public_key

def validateServerSessionBegin(session_key, data):
    isValid = False
    log("RECEIVED {}".format(data))
    # decrypt message with session_key and verify integrity by checking digest
    data = decryptAndVerifyIntegrity(session_key, data)
    log("DECRYPTED {}".format(data))
    if data is not None and data.decode() == SERVER_SESSION_BEGIN:
        isValid = True   
    return isValid

def validateServerAuthReply(session_key, data):
    log("RECEIVED {}".format(data))
    data = decryptAndVerifyIntegrity(session_key, data)
    log("DECRYPTED {}".format(data))
    reply = None
    if data is not None and data.decode() == SERVER_AUTH_REPLY_AUTHORIZED:
        reply = SERVER_AUTH_REPLY_AUTHORIZED
    elif data is not None and data.decode() == SERVER_AUTH_REPLY_UNAUTHORIZED:
        reply = SERVER_AUTH_REPLY_UNAUTHORIZED
    elif data is not None and data.decode() == SERVER_AUTH_REPLY_TERMINATE:
        reply = SERVER_AUTH_REPLY_TERMINATE
    return reply

# helper method for sending encrypted data with a given key
def sendEncrypted(sock, session_key, message_data):
    iv = generateAesIv()
    encrypted_message_data = encryptAndHash(session_key, iv, message_data)
    sock.send(encrypted_message_data)

# method for performing a file upload
def fileUpload(s, session_key):
    log("Performing file upload")
    filename = input("Enter the full name of a file in this directory\n").strip()
    my_file = Path(filename)
    while my_file.is_file() is False:
        filename = input("Please enter a valid file name\n").strip()
        my_file = Path(filename)
    fileSize = os.path.getsize(filename)
    fileSizeBytes = bytes([fileSize])
    print("Sending file size")
    s.send(fileSizeBytes)
    sizeConfirm = s.recv(1024)
    sizeNumber = int.from_bytes(sizeConfirm, "little")
    if(sizeNumber == fileSize):
        print("Proceed with Upload")
        file_to_send = open(filename, 'rb')
        file_data = file_to_send.read()
        s.send(file_data)
    else:
        print("Sizes do not match")
        s.send("END".encode())

# method for performing file download
def fileDownload(s, session_key):
    log("Handling File Download")
    filename = input("Enter the full name of the file you wish to download\n").strip()
    print("Sending requested file name")
    s.send(filename.encode())
    print("Waiting for file size")
    fileSizeData = s.recv(1024)
    fileSize = int.from_bytes(fileSizeData, "little")
    local_file = open("testing.txt", 'wb')
    s.send(fileSizeData)
    print("Waiting for file")
    data = s.recv(fileSize)
    local_file.write(data)
    local_file.close()

# after succesful handshake, the secure session with a server is handled by this method
def handleSecureSession(s, session_key):
    log("Secure session established...")
    # for now, let's just transfer a file as a test
    command = input("Enter a command or 'bye' to exit the program\n")
    s.send(command.strip().upper().encode())
    serverCommand = s.recv(1024)
    serverStringCommand = serverCommand.decode('utf-8')
    while serverStringCommand.strip().upper() != "BYE":
        if command.strip().upper() == FILE_UPLOAD_CMD:
            fileUpload(s)
        elif command.strip().upper() == FILE_RETRIEVE_CMD:
            fileDownload(s)
        command = input("Enter a command or 'bye' to exit the program\n")
        s.send(command.strip().upper().encode())
        serverCommand = s.recv(1024)
        serverStringCommand = serverCommand.decode('utf-8')

# main to establish connection to remote peer and initiate secure session
def main():
    log("STARTING SECURE FILE TRANSFER CLIENT")
    s = socket.socket()   
    log("Attempting to connect to remote peer at {}:{}.".format(REMOTE_HOST_ADDRESS, REMOTE_HOST_PORT))   
    s.connect((REMOTE_HOST_ADDRESS, REMOTE_HOST_PORT))
    log("Connection Successful.")
    handshake_successful, session_key = performHandshake(s)
    if handshake_successful and session_key is not None:
        handleSecureSession(s, session_key)
    else:
        log("Handshake failed. Terminating conneciton")
    s.close()
    print('connection closed')

main()

