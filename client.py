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

with open('ServerKeys/publicKeyDirector.pem','rb') as p:
    serverPublicKeyDirector = rsa.PublicKey.load_pkcs1(p.read())
with open('ServerKeys/publicKeyRegistrar.pem','rb') as p:
    serverPublicKeyRegistrar = rsa.PublicKey.load_pkcs1(p.read())

def authenticateWithServer(clientSocket):
    authCredientials = {}
    print("Enter your name")
    authCredientials['name'] = input()
    print("Enter your roll number")
    authCredientials['rollNumber'] =hashlib.md5(input().encode()).hexdigest()
    authCredientialsString = json.dumps(authCredientials)
    clientSocket.send(authCredientialsString.encode('utf-8'))
    response = clientSocket.recv(6144).decode('utf-8')
    responseJson = json.loads(response)
    print(responseJson['message'])
    return responseJson

def getFileDigest(filePath):
    h = hashlib.sha256()
    with open(filePath,"rb") as f:
        while True:
            chunk = f.read(h.block_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def receiveDegreeCertificate(clientSocket):
    fileName = clientSocket.recv(6144).decode()
    fileSize = clientSocket.recv(6144).decode()
    verificationSignatureDirector = clientSocket.recv(6144)
    verificationSignatureRegistrar = clientSocket.recv(6144)
    
    print("Sending file and authentication certificates")
    receivedFilePath = "ClientReceivedData/"+fileName
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
    print()

def Main():
    host = "127.0.0.1"
    port = 7000
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((host,port))

    authenticationResponse = authenticateWithServer(s)
    if not authenticationResponse['status']:
        return
    receiveDegreeCertificate(s)

Main()
