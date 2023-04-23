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
from fpdf import FPDF
from time import ctime
import warnings
warnings.filterwarnings("ignore")

(publicKeyDirector, privateKeyDirector) = rsa.newkeys(2048)
(publicKeyRegistrar, privateKeyRegistrar) = rsa.newkeys(2048)
with open('ServerKeys\publicKeyDirector.pem','wb') as p:
    p.write(publicKeyDirector.save_pkcs1('PEM'))
with open('ServerKeys\publicKeyRegistrar.pem','wb') as p:
    p.write(publicKeyRegistrar.save_pkcs1('PEM'))

databaseFilePtr = open("credentials.json")
databaseEntries = json.load(databaseFilePtr)

ntpObj = ntplib.NTPClient()

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

    print("[CLIENT AUTHENTICATION REQUEST]  ClientName: "+clientName+" ClientRollNumber: "+userEntry['rollNumber'])
    authenticationResponse = {}

    if foundEntry:
        print("Client Authentication successfull")
        authenticationResponse['status'] = True
        authenticationResponse['message'] = "client authenticated successfully"
    else:
        authenticationResponse['status'] = False
        authenticationResponse['message'] = "client authentication failed"
    print()
    print()
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
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=15)
    finalDetails = {
        "Name":val["name"],
        "Roll Number":val["rollNumber"],
        "DOB":val["dateOfBirth"]        
    }
    for key in val['Subjects'].keys():
        finalDetails[key] = val['Subjects'][key]

    finalDetails['Director Signature'] = "Digitally signed by director" 
    finalDetails['registrar Signature'] = "Digitally signed by registrar" 
    timeRequest = ntpObj.request('europe.pool.ntp.org', version=3)
    finalDetails['Timestamp'] = ctime(timeRequest.tx_time)
    for key, value in finalDetails.items():
        pdf.cell(200, 10, f"{key}: {value}", ln=1)
    pdfName = studentDetails['name']+"_"+studentDetails['rollNumber']+".pdf"
    pdfPath = "ServerData/UnencryptedData/"+pdfName
    pdf.output(pdfPath)
    return pdfPath,pdfName    

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
    print("Sending the files to client")
    # Retriving file hex digest
    print("Generating Hexdigest for the file")
    fileHexDigest = getFileDigest(filePath)
    print(fileHexDigest)
    fileName = p_fileName
    fileSize = os.path.getsize(filePath)

    # Sending the name of fileName
    clientSocket.send(fileName.encode())
    # Sending the fileSize
    clientSocket.send(str(fileSize).encode())
    # Generating hmac
    print("Siging by the private key of Director and Registrar")
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
    print("Sending complete")

def processClient(clientSocket,clientAddress,mutexLock):
    global publicKey, privateKey
    authenticationRequest = json.loads(clientSocket.recv(6144).decode('utf-8'))
    authenticationResponse, userDetails = authenticateClient(authenticationRequest, clientSocket)
    if not authenticationResponse['status']:
        return
    
    print("Generating Encrypted PDF of Degree and Report Card")
    pdfPath,fileName = generatePDF(userDetails['name'], userDetails['rollNumber'])
    pdfPassword = userDetails['dateOfBirth']
    pdfSavePath = "ServerData/EncryptedData/"+fileName
    encryptPDF(pdfPath, pdfPassword,pdfSavePath)
    print()

    sendDegreeCertificate(clientSocket, fileName,pdfSavePath)

    
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
    while(True):
        clientSocket, clientAddress = serverSocket.accept()
        newClientThread = Thread(target= processClient,args= [clientSocket,clientAddress,mutexLock])
        newClientThread.start()

Main()