import socket
from threading import Thread, Lock
import json
import rsa
import hashlib
import tqdm
import time
import pdb

serverPublicKeyDirector = None
serverPublicKeyRegistrar = None
clientPublicKey = None

with open('ServerKeys/publicKeyDirector.pem','rb') as p:
    serverPublicKeyDirector = rsa.PublicKey.load_pkcs1(p.read())
with open('ServerKeys/publicKeyRegistrar.pem','rb') as p:
    serverPublicKeyRegistrar = rsa.PublicKey.load_pkcs1(p.read())
with open('ClientKeys/publicKeyClient.pem','rb') as p:
    clientPublicKey = rsa.PublicKey.load_pkcs1(p.read())

def getFileDigest(filePath):
    h = hashlib.sha256()
    with open(filePath,"rb") as f:
        while True:
            chunk = f.read(h.block_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def verifyOrigin(clientSocket,clientAddress,mutexLock):
    fileName = clientSocket.recv(6144).decode()
    fileSize = clientSocket.recv(6144).decode()
    verificationSignatureDirector = clientSocket.recv(6144)
    verificationSignatureRegistrar = clientSocket.recv(6144)
    verificationSignatureClient = clientSocket.recv(6144)

    receivedFilePath = "ClientReceivedData/Copy/"+fileName
    file = open(receivedFilePath,"wb")
    fileBytes = b""
    isFileEnd = False
    cntStatus = tqdm.tqdm(unit="B",unit_scale=True, unit_divisor=1000,total=int(fileSize))
    while not isFileEnd:
        data = clientSocket.recv(1024)
        if fileBytes[-5:] == b"<END>":
            fileBytes = fileBytes[:-5]
            isFileEnd = True
        else:
            fileBytes += data
        cntStatus.update(1024)
    file.write(fileBytes)
    file.close()
    time.sleep(2)
    print()
    fileHexDigest = getFileDigest(receivedFilePath)
    print(fileHexDigest)
    print()
    print("Verifying hmac for director")
    if rsa.verify(fileHexDigest.encode('ascii'),verificationSignatureDirector,serverPublicKeyDirector) == 'SHA-1':
        print("HMAC Verified for director")
    else:
        print("Message has been tampered with")
    print()
    print("Verifying HMAC for registrar")
    if rsa.verify(fileHexDigest.encode('ascii'), verificationSignatureRegistrar, serverPublicKeyRegistrar) == 'SHA-1':
        print("HMAC Verified for registrar")
    else:
        print("Message has been tampered with")
    print()
    if rsa.verify(fileHexDigest.encode('ascii'), verificationSignatureClient, clientPublicKey) == 'SHA-1':
        print("HMAC Verified for client")
    else:
        print("Message has been tampered with")
    print()
    print()



def Main():
    host = ""
    port = 8000
    mutexLock = Lock()

    # Creating a socket
    serverSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    # Binding to host and port
    serverSocket.bind((host,port))
    # Listening to client in parallel
    serverSocket.listen(10)
    # pdb.set_trace()
    while(True):
        clientSocket, clientAddress = serverSocket.accept()
        newClientThread = Thread(target= verifyOrigin, args= [clientSocket,clientAddress,mutexLock])
        newClientThread.start()
Main()