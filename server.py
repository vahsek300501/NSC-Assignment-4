import socket
from threading import Thread, Lock
import ntplib
import rsa
import hashlib
import pdb
import json
import os
import pdfkit
from pypdf import PdfReader, PdfWriter

(publicKeyDirector, privateKeyDirector) = rsa.newkeys(2048)
(publicKeyRegistrar, privateKeyRegistrar) = rsa.newkeys(2048)
with open('ServerKeys\publicKeyDirector.pem','wb') as p:
    p.write(publicKeyDirector.save_pkcs1('PEM'))
with open('ServerKeys\publicKeyRegistrar.pem','wb') as p:
    p.write(publicKeyRegistrar.save_pkcs1('PEM'))

databaseFilePtr = open("credentials.json")
databaseEntries = json.load(databaseFilePtr)


def authenticateClient(authenticationRequest,clientSocket):
    clientName = authenticationRequest['name']
    clientHashedPassword = authenticationRequest['rollNumber']
    userEntry = None
    foundEntry = False

    for entry in databaseEntries:
        if entry['name'] == clientName and hashlib.md5(entry['rollNumber'].encode()).hexdigest() == clientHashedPassword:
            foundEntry = True
            userEntry = entry
            break

    authenticationResponse = {}

    if foundEntry:
        authenticationResponse['status'] = True
        authenticationResponse['message'] = "client authenticated successfully"
    else:
        authenticationResponse['status'] = False
        authenticationResponse['message'] = "client authentication failed"
    
    authenticationResponseString = json.dumps(authenticationResponse)
    clientSocket.send(authenticationResponseString.encode('utf-8'))
    return authenticationResponse, userEntry


def generatePDF(studentName,studentRollNumber):
    studentDetails = None
    for val in databaseEntries:
        if val['name'] == studentName and val['rollNumber'] == studentRollNumber:
            studentDetails = val
            break
    if studentDetails == None:
        return
    pdfkit.from_string(json.dumps(studentDetails))
    


def encryptPDF(pdfPath,password,pdfName):
    reader = PdfReader(pdfPath)
    writer = PdfWriter()
    writer.append_pages_from_reader(reader)
    writer.encrypt(password)
    with open(pdfName, "wb") as out_file:
        writer.write(out_file)



def getFileDigest(filePath):
    h = hashlib.sha256()
    with open(filePath,"rb") as f:
        while True:
            chunk = f.read(h.block_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def sendDegreeCertificate(clientSocket,p_fileName,filePath):
    print(filePath)
    # Retriving file hex digest
    fileHexDigest = getFileDigest(filePath)
    print(fileHexDigest)
    fileName = p_fileName
    fileSize = os.path.getsize(filePath)

    # Sending the name of fileName
    clientSocket.send(fileName.encode())
    # Sending the fileSize
    clientSocket.send(str(fileSize).encode())
    # Generating hmac
    verificationSignatureDirector = rsa.sign(fileHexDigest.encode('ascii'), privateKeyDirector, 'SHA-1')
    verificationSignatureRegistrar = rsa.sign(fileHexDigest.encode('ascii'),privateKeyRegistrar , 'SHA-1')
    # Sending Hmac
    clientSocket.send(verificationSignatureDirector)
    clientSocket.send(verificationSignatureRegistrar)

    file = open(filePath,"rb")
    data = file.read()
    clientSocket.sendall(data)
    clientSocket.send(b'<END>')
    file.close()
    clientSocket.close()


def processClient(clientSocket,clientAddress,mutexLock):
    global publicKey, privateKey
    authenticationRequest = json.loads(clientSocket.recv(6144).decode('utf-8'))
    authenticationResponse, userDetails = authenticateClient(authenticationRequest, clientSocket)
    if not authenticationResponse['status']:
        return
    pdfPassword = userDetails['dateOfBirth']
    pdfPath = "ServerData/UnencryptedData/test.pdf"
    pdfSavePath = "ServerData/EncryptedData/test.pdf"
    encryptPDF(pdfPath, pdfPassword,pdfSavePath)
    sendDegreeCertificate(clientSocket, "test.pdf",pdfSavePath)

    
    



def Main():
    host = ""
    port = 7000
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
        newClientThread = Thread(target= processClient,args= [clientSocket,clientAddress,mutexLock])
        newClientThread.start()
Main()

# fileHex = getFileDigest("C:\\Users\\kesha\\Desktop\\Assignment-4\\ServerData\\test.pdf")
# print(fileHex)

# generatePDF("Keshav", 2019249)
# pdfPassword = "300501"
# pdfPath = "ServerData/UnencryptedData/test.pdf"
# pdfSavePath = "ServerData/EncryptedData/test.pdf"
# encryptPDF(pdfPath, pdfPassword, pdfSavePath)