import socket
import bluetooth
from protocolConstants import *

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
    file_to_send = open('testFile.txt', 'rb')
    file_data = file_to_send.read()
    s.send(file_data)

# after succesful handshake, the secure session with a server is handled by this method
def handleSecureSession(s):
    log("Secure session established...")
    # for now, let's just transfer a file as a test
    fileUpload(s)

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

