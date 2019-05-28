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
# file name for encrypted file storing usernames and hashed passwords
USERS_FILENAME = "users"
# dictionary to store usernames and hashed passwords
USER_DATABASE = {}

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
    isValidUser, persistence_key, masked_user_directory = handleClientAuth(conn, session_key)
    if not isValidUser:
        log("Handshake Failed.")
        return False, None

    client_secure_session_keys = ClientSecureSessionKeys(session_key, persistence_key, masked_user_directory)

    log("Handshake Successful.")
    return True, client_secure_session_keys

# object to hold the session key (for secure communications with the client)
# and persistence key (for storing/retrieving user files on the server's local file system).
# Both keys are produced during the handshake. The session key is unique to a session for a given user,
# but the persistence key is the same for a given user across all sessions for that user.
class ClientSecureSessionKeys:
    def __init__(self, session_key, persistence_keys, masked_user_directory):
        self.session_key = session_key
        self.persistence_keys = persistence_keys
        self.masked_user_directory = masked_user_directory

# method to handle client authentication
def handleClientAuth(conn, session_key):
    isValidUser = False
    persistence_key = None
    masked_user_directory = None
    loginAttempts = 0
    while not isValidUser and loginAttempts < MAX_AUTH_ATTEMPTS:
        # *** wait for CLIENT AUTH message ***
        data = conn.recv(1024)
        # validate CLIENT AUTH
        if data:
            isValidUser, persistence_key, masked_user_directory = validateClientAuth(data, session_key)
            if isValidUser:
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
    return isValidUser, persistence_key, masked_user_directory

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
    client_public_key = None
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
        first_segment = data[0:256]  # COMMAND + SESSION KEY encrypted with server's public key
        client_signature = data[256:]  # Client Signature of Session Key
        # decrypt first segment with server's private key
        first_segment_data = rsa_decrypt(rsa_key_pair, first_segment)
        log("DECRYPTED with Ksv- {}".format(first_segment_data))
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
    persistence_key = None
    masked_user_directory = None
    log("RECEIVED {}".format(data))
    data = decryptAndVerifyIntegrity(session_key, data)
    log("DECRYPTED {}".format(data))
    tokens = data.decode().split(" ")
    if len(tokens) == 4:
        cmd = tokens[0] + " " + tokens[1]
        if cmd == CLIENT_AUTH:
            username = tokens[2]
            password = tokens[3]
            if username is not None and username != '' and password is not None and password != '':
                hashed_password = sha256HexDigest(password.encode())
                if authenticate_user(username, hashed_password):
                    isValid = True
                    persistence_key = generatePersistenceKeyFromPassword(password)
                    masked_user_directory = generateMaskedText(username.encode(), persistence_key)
    return isValid, persistence_key, masked_user_directory

def authenticate_user(username, hashed_password):
    valid_user = False
    # check if user is registered in database
    if username in USER_DATABASE:
        # compare hashed password user provided in client auth message with stored hashed password
        valid_user = True if hashed_password == USER_DATABASE[username] else False
    return valid_user

'''
Helper methods for storing and retrieving encrypted files
'''
def generateMaskedFileName(plaintext_filename, persistence_key):
    # filename is a keyed hash of the plaintext_filename, where the key used
    # for the hash is the user's persistence key
    return generateMaskedText(plaintext_filename.encode(), persistence_key)

# given plaintext filename, create a masked file name, then encrypt/hash file data with persistence key
# and write to file
def storeFileEncrypted(plaintext_filename, plaintext_file_data, persistence_key):
    masked_filename = generateMaskedFileName(plaintext_filename, persistence_key)
    writeEncryptedFile(masked_filename, plaintext_file_data, persistence_key)

# given masked filename, find file with masked name, read in encrypted file,
#  decrypt with user's persistence key and return plaintext file data
def retrieveEncryptedFile(masked_file_name, persistence_key):
    decrypted_file_data = getEncryptedFileData(masked_file_name, persistence_key)
    return decrypted_file_data

# helper method for sending encrypted data with a given key
def sendEncrypted(sock, session_key, message_data):
    iv = generateAesIv()
    encrypted_message_data = encryptAndHash(session_key, iv, message_data)
    sock.send(encrypted_message_data)

# method for handling a file upload
def handleFileUpload(sock, client_secure_session_keys):
    log("Handling File Upload")
    print("Waiting for file name")
    filename_bytes = decryptAndVerifyIntegrity(client_secure_session_keys.session_key, sock.recv(1024))
    filename = filename_bytes.decode('utf-8')
    print("Filename")
    print(filename)
    sendEncrypted(sock, client_secure_session_keys.session_key, filename.encode())
    print("Waiting for file size")
    fileSizeData = decryptAndVerifyIntegrity(client_secure_session_keys.session_key, sock.recv(1024))
    fileSizeString = fileSizeData.decode('utf-8')
    fileSizeInt = int(fileSizeString)
    print("File size")
    print(fileSizeInt)
    sendEncrypted(sock, client_secure_session_keys.session_key, fileSizeString.encode())
    bytes_read = 0
    encrypted_data = b""
    while(bytes_read < fileSizeInt):
        next_chunk = sock.recv(1024)
        print(len(next_chunk))
        bytes_read = bytes_read + len(next_chunk)
        print(bytes_read)
        encrypted_data = encrypted_data + next_chunk
    print(len(encrypted_data))
    data = decryptAndVerifyIntegrity(client_secure_session_keys.session_key, encrypted_data)
    storeFileEncrypted(filename, data, client_secure_session_keys.persistence_keys)

# method for handling a file download
def handleFileDownload(s, client_secure_session_keys):
    print("Waiting for requested file name")
    requestedFileName = decryptAndVerifyIntegrity(client_secure_session_keys.session_key, s.recv(1024))
    fileNameString = requestedFileName.decode('utf-8')
    print(fileNameString)
    masked_file_name = generateMaskedFileName(fileNameString, client_secure_session_keys.persistence_keys)
    my_file = Path(masked_file_name)
    if my_file.is_file() is True:
        print("File found")
        file_data = retrieveEncryptedFile(masked_file_name, client_secure_session_keys.persistence_keys)
        iv = generateAesIv()
        encrypted_message_data = encryptAndHash(client_secure_session_keys.session_key, iv, file_data)
        fileSizeString = str(len(encrypted_message_data))
        print("Sending file size")
        sendEncrypted(s, client_secure_session_keys.session_key, fileSizeString.encode())
        returnFileSize = decryptAndVerifyIntegrity(client_secure_session_keys.session_key, s.recv(1024))
        returnFileSizeString = returnFileSize.decode('utf-8')
        if (returnFileSizeString == fileSizeString):
            print("Proceed with Upload")
            bytes_sent = 0
            encrypted_data_size = len(encrypted_message_data)
            while (bytes_sent < encrypted_data_size):
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
        print("File not found")

# after succesful handshake, the client's secure session is handled by this method
def handleSecureSession(sock, client_secure_session_keys):
    log("Secure session established...")
    command = decryptAndVerifyIntegrity(client_secure_session_keys.session_key, sock.recv(1024))
    stringData = command.decode('utf-8')
    print("Waiting for first command")
    while stringData.strip().upper() != EXIT_COMMAND:
        print("In command loop")
        if stringData.strip().upper() == FILE_UPLOAD_CMD:
            sendEncrypted(sock, client_secure_session_keys.session_key, FILE_UPLOAD_CMD.encode())
            handleFileUpload(sock, client_secure_session_keys)
        elif stringData.strip().upper() == FILE_RETRIEVE_CMD:
            sendEncrypted(sock, client_secure_session_keys.session_key, FILE_RETRIEVE_CMD.encode())
            handleFileDownload(sock, client_secure_session_keys)
        print("Awaiting New Command")
        command = decryptAndVerifyIntegrity(client_secure_session_keys.session_key, sock.recv(1024))
        stringData = command.decode('utf-8')
    # for now, let's just transfer a file as a test
    # handleFileUpload(sock)
    sendEncrypted(sock, client_secure_session_keys.session_key, EXIT_COMMAND.encode())

def initializeUsersDatabase():
    log("Initializing users database.")
    global USER_DATABASE
    users_file = Path(USERS_FILENAME)
    if not users_file.is_file():
        # users file does not exist, so create it with seeded data
        writeUsersFile(MASTER_KEY, USERS_FILENAME, createMockUserDataForFile())
    # read user data and store in user dictionary
    USER_DATABASE = readUsersFile(MASTER_KEY, USERS_FILENAME)

# helper method for logging. Logging controlled with global flag.
def log(message):
    if LOGGING_ENABLED:
        print(message)

# Main method for accepting connection and initiating secure sessions
def main():
    log("STARTING SECURE FILE TRANSFER SERVER")
    initializeUsersDatabase()
    s = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    s.bind(("", SERVER_PORT))
    s.listen(5)                
    log('Server listening on port {}.'.format(SERVER_PORT))
    while True:
        log("Waiting for connection...")
        conn, addr = s.accept()     
        log("Accepted connection from {}.".format(addr))
        handshake_successful, client_secure_session_keys = performHandshake(conn)
        if handshake_successful and client_secure_session_keys is not None:
            handleSecureSession(conn, client_secure_session_keys)
        else:
            log("Handshake failed. Terminating conneciton")
        log("Secure session ended. Closing connection.")
        conn.close()

main()
