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
    try:
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
    except:
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
    # build 1st segment of message
    message = message + session_key
    # encrypt 1st segment of message with the server's public key, so only server can use this session key
    session_key_message_cipher_text = rsa_encrypt(server_public_key, message)
    # sign session key with client's private key
    signature = rsa_sign(rsa_key_pair, session_key)
    # build full message: 1st segment + signature
    complete_message = session_key_message_cipher_text + signature
    # encrypt and hash full message with MASTER_KEY
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
    sendEncrypted(s, session_key, filename.encode())
    fileNameConfirmData = decryptAndVerifyIntegrity(session_key, s.recv(1024))
    fileNameConfirm = fileNameConfirmData.decode('utf-8')
    if filename != fileNameConfirm:
        print("Filenames do not match")
        sendEncrypted(s, session_key, "END".encode())
        return
    file_to_send = open(filename, 'rb')
    file_data = file_to_send.read()
    iv = generateAesIv()
    encrypted_message_data = encryptAndHash(session_key, iv, file_data)
    fileSizeString = str(len(encrypted_message_data))
    print("Sending file size")
    print(fileSizeString)
    sendEncrypted(s, session_key, fileSizeString.encode())
    sizeConfirm = decryptAndVerifyIntegrity(session_key, s.recv(1024))
    sizeConfirmString = sizeConfirm.decode('utf-8')
    if(sizeConfirmString == fileSizeString):
        print("Proceed with Upload")
        bytes_sent = 0
        encrypted_data = b""
        encrypted_data_size = len(encrypted_message_data)
        while(bytes_sent < encrypted_data_size):
            chunk_size = 1024
            if chunk_size > len(encrypted_message_data):
                chunk_size = len(encrypted_message_data)
            next_chunk = encrypted_message_data[0:chunk_size]
            bytes_sent = bytes_sent + len(next_chunk)
            trim_size = 1024
            if len(encrypted_message_data) < 1024:
                trim_size = len(encrypted_message_data)
            encrypted_message_data = encrypted_message_data[trim_size:]
            s.send(next_chunk)
        print(bytes_sent)
    else:
        print("Sizes do not match")
        sendEncrypted(s, session_key, "END".encode())
    print("Wait for server file upload response")
    serverUploadResponse = decryptAndVerifyIntegrity(session_key, s.recv(1024))
    serverResponseString = serverUploadResponse.decode('utf-8')
    if(serverResponseString == "SUCCESS"):
        print("Upload Succeeded")
        os.remove(filename)
    else:
        print("Upload Failed")

# method for performing file download
def fileDownload(s, session_key):
    log("Handling File Download")
    filename = input("Enter the full name of the file you wish to download\n").strip()
    print("Sending requested file name")
    sendEncrypted(s, session_key, filename.encode())
    print("Waiting for file size")
    fileSizeData = decryptAndVerifyIntegrity(session_key, s.recv(1024))
    fileSizeString = fileSizeData.decode('utf-8')
    if(fileSizeString is not FNF_COMMAND):
        fileSizeInt = int(fileSizeString)
        print("File Size")
        print(fileSizeString)
        local_file = open(filename, 'wb')
        sendEncrypted(s, session_key, fileSizeData)
        print("Waiting for file")
        bytes_read = 0
        encrypted_data = b""
        while (bytes_read < fileSizeInt):
            next_chunk = s.recv(1024)
            print(len(next_chunk))
            bytes_read = bytes_read + len(next_chunk)
            print(bytes_read)
            encrypted_data = encrypted_data + next_chunk
        print(len(encrypted_data))
        data = decryptAndVerifyIntegrity(session_key, encrypted_data)
        local_file.write(data)
        local_file.close()
        print("Send download confirmation to server")
        sendEncrypted(s, session_key, "SUCCESS".encode())
    else:
        print("File Not Found On Server")

# after succesful handshake, the secure session with a server is handled by this method
def handleSecureSession(s, session_key):
    log("Secure session established...")
    # for now, let's just transfer a file as a test
    command = input("Enter a command or 'bye' to exit the program\n")
    sendEncrypted(s, session_key, command.strip().upper().encode())
    serverCommand = decryptAndVerifyIntegrity(session_key, s.recv(1024))
    serverStringCommand = serverCommand.decode('utf-8')
    while serverStringCommand.strip().upper() != "BYE":
        if serverStringCommand.strip().upper() == FILE_UPLOAD_CMD:
            fileUpload(s, session_key)
        elif serverStringCommand.strip().upper() == FILE_RETRIEVE_CMD:
            fileDownload(s, session_key)
        else:
            print(serverStringCommand)
        command = input("Enter a command or 'bye' to exit the program\n")
        sendEncrypted(s, session_key, command.strip().upper().encode())
        serverCommand = decryptAndVerifyIntegrity(session_key, s.recv(1024))
        serverStringCommand = serverCommand.decode('utf-8')


# main to establish connection to remote peer and initiate secure session
def main():
    log("STARTING SECURE FILE TRANSFER CLIENT")
    s = socket.socket()
    try:
        log("Attempting to connect to remote peer at {}:{}.".format(REMOTE_HOST_ADDRESS, REMOTE_HOST_PORT))
        s.connect((REMOTE_HOST_ADDRESS, REMOTE_HOST_PORT))
        log("Connection Successful.")
        handshake_successful, session_key = performHandshake(s)
        if handshake_successful and session_key is not None:
            handleSecureSession(s, session_key)
        else:
            log("Handshake failed. Terminating connection")
        s.close()
    except:
        log("Connection terminated unexpectedly.")
    log('connection closed')

main()

