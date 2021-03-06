import socket
import bluetooth
from protocolConstants import *
from pathlib import Path
import os
from cryptoutil import *


# flag to turn logging on or off
LOGGING_ENABLED = True
# port on which the server listens for incoming connections
SERVER_PORT = 3
# max client authentication attempts before disconnecting from client
MAX_AUTH_ATTEMPTS = 3
# master key
MASTER_KEY = b'*%Hah%zgh&hFL#Db'

# method for handling secure handshake
def performHandshake(conn):
    log("Starting secure handshake...")
    session_key = None
    rsa_key_pair = None
    client_public_key = None

    # *** wait for CLIENT HELLO ***
    data = conn.recv(1024)
    # validate CLIENT HELLO
    if data:
        isValid, client_public_key = validateClientHello(data)
        if isValid:
            message, rsa_key_pair = buildServerHello()
            log("SENDING {}".format(message))
            conn.send(message)
    else:
        log("Handshake Failed.")
        return False, None

    # *** wait for KEY EXCHANGE ***
    data = conn.recv(1024)
    # validate KEY EXCHANGE
    if data:
        isValid, session_key = validateKeyExchange(data, rsa_key_pair, client_public_key)
        if isValid:
            message = buildServerSessionBegin(session_key)
            log("SENDING {}".format(message))
            conn.send(message)
    else:
        log("Handshake Failed.")
        return False, None

    # *** wait for CLIENT SESSION BEGIN ***
    data = conn.recv(1024)
    # validate CLIENT SESSION BEGIN
    if data and validateClientSessionBegin(session_key, data):
        log("Waiting for client authentication...")
    else:
        log("Handshake Failed.")
        return False, None

    # handle client authentication
    if not handleClientAuth(conn, session_key):
        log("Handshake Failed.")
        return False, None

    log("Handshake Successful.")
    return True, session_key

# method to handle client authentication
def handleClientAuth(conn, session_key):
    isValidUser = False
    loginAttempts = 0
    while not isValidUser and loginAttempts < MAX_AUTH_ATTEMPTS:
        # *** wait for CLIENT AUTH message ***
        data = conn.recv(1024)
        # validate CLIENT AUTH
        if data:
            if validateClientAuth(data, session_key):
                isValidUser = True
                message = buildServerAuthReplyAuthorized(session_key)
                log("SENDING {}".format(message))
                conn.send(message)
            else:
                loginAttempts = loginAttempts + 1
                message = ''
                if loginAttempts >= MAX_AUTH_ATTEMPTS:
                    message = buildServerAuthReplyTerminate(session_key)
                else:
                    message = buildServerAuthReplyUnauthorized(session_key)
                log("SENDING {}".format(message))
                conn.send(message)
        else:
            break
    return isValidUser

###
# Helper methods for constructing server side protocol handshake messages
###
def buildServerHello():
    message = SERVER_HELLO.encode()
    # generate rsa public key pair and export public key to share with client
    rsa_key_pair = generateRsaPublicKeyPair()
    exported_public_key = getPublicKeyToExport(rsa_key_pair)
    # build and encrypt message
    message = message + exported_public_key
    iv = generateAesIv()
    message = encryptAndHash(MASTER_KEY, iv, message)
    return message, rsa_key_pair

def buildServerSessionBegin(session_key):
    message = SERVER_SESSION_BEGIN.encode()
    # generate counter, add to message...and encrypt
    iv = generateAesIv()
    message = encryptAndHash(session_key, iv, message)
    return message

def buildServerAuthReplyAuthorized(session_key):
    message = SERVER_AUTH_REPLY_AUTHORIZED.encode()
    # Encrypt
    iv = generateAesIv()
    message = encryptAndHash(session_key, iv, message)
    return message

def buildServerAuthReplyUnauthorized(session_key):
    message = SERVER_AUTH_REPLY_UNAUTHORIZED.encode()
    # Encrypt
    iv = generateAesIv()
    message = encryptAndHash(session_key, iv, message)
    return message

def buildServerAuthReplyTerminate(session_key):
    message = SERVER_AUTH_REPLY_TERMINATE.encode()
    # Encrypt
    iv = generateAesIv()
    message = encryptAndHash(session_key, iv, message)
    return message

def buildConnectionClosed(session_key):
    message = CONNECTION_CLOSED.encode()
    # encrypt
    iv = generateAesIv()
    message = encryptAndHash(session_key, iv, message)
    return message

###
# Helper methods for validating commands in the handshake process on server side.
###

def parseCommandFromPayload(data, expected_command):
    command = data[0:len(expected_command)]
    payload = data[len(expected_command):]
    return command, payload

def validateClientHello(data):
    isValid = False
    log("RECEIVED {}".format(data))
    # decrypt message with mastery key and verify integrity by checking digest
    data = decryptAndVerifyIntegrity(MASTER_KEY, data)
    log("DECRYPTED {}".format(data))
    if data is not None:
        command, payload = parseCommandFromPayload(data, CLIENT_HELLO)
        if command.decode() == CLIENT_HELLO:
            client_public_key = importPublicKey(payload)
            if client_public_key is not None:
                isValid = True
            else:
                log("Error: Received malformed public key from client.")
        else:
            log("Error: Received unexpected command during handshake.")
    return isValid, client_public_key

def validateKeyExchange(data, rsa_key_pair, client_public_key):
    isValid = False
    session_key = None
    log("RECEIVED {}".format(data))
    # decrypt message with mastery key and verify integrity by checking digest
    data = decryptAndVerifyIntegrity(MASTER_KEY, data)
    if data is not None:
        # parse key exchange message into two segments
        first_segment = data[0:256]  # COMMAND + SESSION KEY
        second_segment = data[256:]  # Client Signature of Session Key
        # decrypt each segment with server's private key
        first_segment_data = rsa_decrypt(rsa_key_pair, first_segment)
        log("DECRYPTED with Km and Ksv- {}".format(first_segment_data))
        client_signature = rsa_decrypt(rsa_key_pair, second_segment)
        log("DECRYPTED with Km and Ksv- {}".format(second_segment))
        # parse first segment of message
        command, payload = parseCommandFromPayload(first_segment_data, KEY_EXCHANGE)
        if command.decode() == KEY_EXCHANGE:
            if len(payload) == 32:
                session_key = payload
                # verify that the client signed this session_key
                is_verified = rsa_verify_signature(client_public_key, session_key, client_signature)
                if is_verified:
                     log("Verified key was signed by client.")
                     isValid = True
                else:
                    log("Error: could not verify client signed session key")
            else:
                log("Error: invalid session key received from client.")
        else:
            log("Error: Received unexpected command during handshake.")
    return isValid, session_key

def validateClientSessionBegin(session_key, data):
    isValid = False
    log("RECEIVED {}".format(data))
    data = decryptAndVerifyIntegrity(session_key, data)
    log("DECRYPTED {}".format(data))
    if data is not None and data.decode() == CLIENT_SESSION_BEGIN:
        isValid = True   
    return isValid

def validateClientAuth(data, session_key):
    isValid = False
    log("RECEIVED {}".format(data))
    data = decryptAndVerifyIntegrity(session_key, data)
    log("DECRYPTED {}".format(data))
    tokens = data.decode().split(" ")
    if len(tokens) == 4:
        cmd = tokens[0] + " " + tokens[1]
        if cmd == CLIENT_AUTH:
            username = tokens[2]
            password = tokens[3]
            if (username == "peter" or username == "will") and password == "pwd":
                isValid = True
    return isValid

# method for handling a file upload
def handleFileUpload(sock):
    log("Handling File Upload")
    print("Waiting for file size")
    fileSizeData = sock.recv(1024)
    fileSize = int.from_bytes(fileSizeData, "little")
    sock.send(fileSizeData)
    local_file = open('transferTestFile.txt', 'wb')
    data = sock.recv(fileSize)
    local_file.write(data)
    local_file.close()

# method for handling a file download
def handleFileDownload(s):
    print("Waiting for requested file name")
    requestedFileName = s.recv(1024)
    fileNameString = requestedFileName.decode('utf-8')
    print(fileNameString)
    my_file = Path(fileNameString)
    if my_file.is_file() is True:
        print("File found")
        fileSize = os.path.getsize(fileNameString)
        fileSizeBytes = bytes([fileSize])
        print("Sending file size")
        s.send(fileSizeBytes)
        returnFileSize = s.recv(1024)
        if returnFileSize == fileSizeBytes:
            file_to_send = open(fileNameString, 'rb')
            file_data = file_to_send.read()
            s.send(file_data)
    else:
        print("File not found")

# after succesful handshake, the client's secure session is handled by this method
def handleSecureSession(sock):
    log("Secure session established...")
    command = sock.recv(1024)
    stringData = command.decode('utf-8')
    print("Waiting for first command")
    while stringData.strip().upper() != EXIT_COMMAND:
        print("In command loop")
        if stringData.strip().upper() == FILE_UPLOAD_CMD:
            sock.send(FILE_UPLOAD_CMD.encode())
            handleFileUpload(sock)
        elif stringData.strip().upper() == FILE_RETRIEVE_CMD:
            sock.send(FILE_RETRIEVE_CMD.encode())
            handleFileDownload(sock)
        print("Awaiting New Command")
        command = sock.recv(1024)
        stringData = command.decode('utf-8')
    # for now, let's just transfer a file as a test
    # handleFileUpload(sock)
    sock.send(EXIT_COMMAND.encode())

# helper method for logging. Logging controlled with global flag.
def log(message):
    if LOGGING_ENABLED:
        print(message)

# Main method for accepting connection and initiating secure sessions
def main():
    log("STARTING SECURE FILE TRANSFER SERVER")
    s = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    s.bind(("", SERVER_PORT))
    s.listen(5)                
    log('Server listening on port {}.'.format(SERVER_PORT))
    while True:
        log("Waiting for connection...")
        conn, addr = s.accept()     
        log("Accepted connection from {}.".format(addr))
        handshake_succcess, session_key = performHandshake(conn)
        if handshake_succcess:
            handleSecureSession(conn)
        else:
            log("Handshake failed. Terminating conneciton")
        log("Secure session ended. Closing connection.")
        conn.close()

main()
