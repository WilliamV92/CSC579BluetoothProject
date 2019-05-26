import socket
import bluetooth
from protocolConstants import *
from pathlib import Path
import os

# flag to turn logging on or off
LOGGING_ENABLED = True
# port on which the server listens for incoming connections
SERVER_PORT = 3
# max client authentication attempts before disconnecting from client
MAX_AUTH_ATTEMPTS = 3

# method for handling secure handshake
def performHandshake(conn):
    log("Starting secure handshake...")
    # *** wait for CLIENT HELLO ***
    data = conn.recv(1024)
    # validate CLIENT HELLO
    if data and validateClientHello(data.decode()):
        message = buildServerHello()
        log("SENDING {}".format(message))
        conn.send(message.encode())
    else:
        log("Handshake Failed.")
        return False

    # *** wait for KEY EXCHANGE ***
    data = conn.recv(1024)
    # validate KEY EXCHANGE
    if data and validateKeyExchange(data.decode()):
        message = buildServerSessionBegin()
        log("SENDING {}".format(message))
        conn.send(message.encode())
    else:
        log("Handshake Failed.")
        return False

    # *** wait for CLIENT SESSION BEGIN ***
    data = conn.recv(1024)
    # validate CLIENT SESSION BEGIN
    if data and validateClientSessionBegin(data.decode()):
        log("Waiting for client authentication...")
    else:
        log("Handshake Failed.")
        return False

    # handle client authentication
    if not handleClientAuth(conn):
        log("Handshake Failed.")
        return False

    log("Handshake Successful.")
    return True

# method to handle client authentication
def handleClientAuth(conn):
    isValidUser = False
    loginAttempts = 0
    while not isValidUser and loginAttempts < MAX_AUTH_ATTEMPTS:
        # *** wait for CLIENT AUTH message ***
        data = conn.recv(1024)
        # validate CLIENT AUTH
        if data:
            if validateClientAuth(data.decode()):
                isValidUser = True
                message = buildServerAuthReplyAuthorized()
                log("SENDING {}".format(message))
                conn.send(message.encode())
            else:
                loginAttempts = loginAttempts + 1
                message = ''
                if loginAttempts >= MAX_AUTH_ATTEMPTS:
                    message = buildServerAuthReplyTerminate()
                else:
                    message = buildServerAuthReplyUnauthorized()
                log("SENDING {}".format(message))
                conn.send(message.encode())
        else:
            break
    return isValidUser

###
# Helper methods for constructing server side protocol handshake messages
###
def buildServerHello():
    message = SERVER_HELLO
    # generate key, hash, and add to message...and encrypt
    return message

def buildServerSessionBegin():
    message = SERVER_SESSION_BEGIN
    # generate counter, add to message...and encrypt
    return message

def buildServerAuthReplyAuthorized():
    message = SERVER_AUTH_REPLY_AUTHORIZED
    # Encrypt
    return message

def buildServerAuthReplyUnauthorized():
    message = SERVER_AUTH_REPLY_UNAUTHORIZED
    # Encrypt
    return message

def buildServerAuthReplyTerminate():
    message = SERVER_AUTH_REPLY_TERMINATE
    # Encrypt
    return message

def buildConnectionClosed():
    message = CONNECTION_CLOSED
    # encrypt
    return message

###
# Helper methods for validating commands in the handshake process on server side.
###
def validateClientHello(data):
    isValid = False
    log("RECEIVED {}".format(data))
    if data == CLIENT_HELLO:
        isValid = True
    return isValid

def validateKeyExchange(data):
    isValid = False
    log("RECEIVED {}".format(data))
    if data == KEY_EXCHANGE:
        isValid = True
    return isValid

def validateClientSessionBegin(data):
    isValid = False
    log("RECEIVED {}".format(data))
    if data == CLIENT_SESSION_BEGIN:
        isValid = True   
    return isValid

def validateClientAuth(data):
    isValid = False
    log("RECEIVED {}".format(data))
    tokens = data.split(" ")
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
        handshake_succcess = performHandshake(conn)
        if handshake_succcess:
            handleSecureSession(conn)
        else:
            log("Handshake failed. Terminating conneciton")
        log("Secure session ended. Closing connection.")
        conn.close()

main()
