import socket
import bluetooth
from protocolConstants import *
from pathlib import Path
import os


# flag to turn logging on or off
LOGGING_ENABLED = True
# address of remote peer (Bluetooth address)
REMOTE_HOST_ADDRESS = '54:8C:A0:A8:EA:E4'
# port on which remote peer is listening
REMOTE_HOST_PORT = 3

# helper method for logging. Logging controlled with global flag.
def log(message):
    if LOGGING_ENABLED:
        print(message)

# method for handling secure handshake
def performHandshake(s):
    log("Starting secure handshake...")
    # send CLIENT HELLO
    message = buildClientHello()
    log("SENDING {}".format(message))
    s.send(message.encode())

    # *** wait for SERVER HELLO ***
    data = s.recv(1024)
    # validate SERVER HELLO
    if data and validateServerHello(data.decode()):
        message = buildKeyExchange()
        log("SENDING {}".format(message))
        s.send(message.encode())
    else:
        log("Handshake Failed.")
        return False

    # *** wait for SERVER SESSION BEGIN ***
    data = s.recv(1024)
    # validate SERVER SESSION BEGIN
    if data and validateServerSessionBegin(data.decode()):
        message = buildClientSessionBegin()
        log("SENDING {}".format(message))
        s.send(message.encode())
    else:
        log("Handshake Failed.")
        return False

    # perform client authentication
    if not performClientAuthentication(s):
        log("Handshake Failed.")
        return False

    log("Handshake Successful.")
    return True

def performClientAuthentication(s):
    authSuccess = False
    while not authSuccess:
        # get username and password
        username = input("Enter username: ")
        password = input("Enter password: ")
        # build CLIENT AUTH message and send
        message = buildClientAuth(username, password)
        log("SENDING {}".format(message))
        s.send(message.encode())
        # *** wait for SERVER AUTH REPLY ***
        data = s.recv(1024)
        # validate SERVER AUTH REPLY
        if data:
            if data.decode() == SERVER_AUTH_REPLY_TERMINATE:
                # if max client auth attempts exceeded, server drops connection.
                log("RECEIVED {}".format(data.decode()))
                break
            elif validateServerAuthReply(data.decode()):
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
    message = CLIENT_HELLO
    # generate key, hash, and add to message...and encrypt
    return message

def buildKeyExchange():
    message = KEY_EXCHANGE
    # generate key, hash and add to message...and encrypt
    return message

def buildClientSessionBegin():
    message = CLIENT_SESSION_BEGIN
    # generate counter, add to message...and encrypt
    return message

def buildClientAuth(username, password):
    message = CLIENT_AUTH + " " + username + " " + password
    # encrypt
    return message

###
# Helper methods for validating commands in the handshake process on client side.
###
def validateServerHello(data):
    isValid = False
    log("RECEIVED {}".format(data))
    if data == SERVER_HELLO:
        isValid = True
    return isValid

def validateServerSessionBegin(data):
    isValid = False
    log("RECEIVED {}".format(data))
    if data == SERVER_SESSION_BEGIN:
        isValid = True   
    return isValid

def validateServerAuthReply(data):
    isValid = False
    log("RECEIVED {}".format(data))
    if data == SERVER_AUTH_REPLY_AUTHORIZED:
        isValid = True
    elif data == SERVER_AUTH_REPLY_UNAUTHORIZED:
        isValid = False
    return isValid

# method for performing a file upload
def fileUpload(s):
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
def fileDownload(s):
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
def handleSecureSession(s):
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
    s = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
    log("Attempting to connect to remote peer at {}:{}.".format(REMOTE_HOST_ADDRESS, REMOTE_HOST_PORT))   
    s.connect((REMOTE_HOST_ADDRESS, REMOTE_HOST_PORT))
    log("Connection Successful.")
    performHandshake(s)
    handleSecureSession(s)
    s.close()
    print('connection closed')

main()

