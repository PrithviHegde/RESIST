from hashlib import sha256
from Crypto.Cipher import AES
import pyrebase
import firebase_admin
from firebase_admin import credentials, firestore
import random
import secrets
import csv
from math import log
from time import time

#Merkle Tree Node class
class Node:
    #Constructor for the Node class
    def __init__(self, left, right, value: str, content) -> None:
        self.left: Node = left
        self.right: Node = right
        self.value: str = value
        self.content = content

    #Method to hash val    
    @staticmethod
    def hashFile(val: str) -> str:
        return sha256(val.encode('UTF-8')).hexdigest()


#Merkle Tree class       
class MerkleTree:
    leaves: list[Node]
    root: Node

    #Constructor for MerkleTree class
    def __init__(self, values: list[str]) -> None:
        self.__buildTree(values)
 

    #buildTree function caller
    def __buildTree(self, values: list[str]) -> None:
 
        self.leaves = [Node(None, None, Node.hashFile(val), val) for val in values] #create list of empty nodes for leaves

        if len(self.leaves) % 2 == 1:
            self.leaves.append(Node(None, None, "0"*1, '_'*1))  # padding 0s if odd number of elements


        self.root = self.__buildTreeRec(self.leaves)
 
    #buildTree actual function
    def __buildTreeRec(self, nodes: list[Node]) -> Node:
        if len(nodes) % 2 == 1:
            nodes.append(Node(None, None, "0"*1, '_'*1))  # padding 0s if odd number of elements #is this needed???
        
        half = len(nodes) // 2
 
        #if there are only 2 nodes, use them to build their root
        if len(nodes) == 2:
            return Node(nodes[0], nodes[1], Node.hashFile(nodes[0].value + nodes[1].value), nodes[0].content+nodes[1].content)

        #otherwise, recursive calls
        left: Node = self.__buildTreeRec(nodes[:half])
        right: Node = self.__buildTreeRec(nodes[half:])
        value: str = Node.hashFile(left.value + right.value)
        content: str = left.content + right.content

        return Node(left, right, value, content)
    

    #returns the list of leaf nodes
    def getLeaves(self)-> list[Node]:
        '''returns the list of leaf Node objects for a MT class object'''
        return self.leaves


    #Function to print a MT
    def printTree(self) -> None:
        self.__printTreeRec(self.root)
         
    def __printTreeRec(self, node: Node) -> None:
        #if the node is a leaf
        if not node.left: 
            print("Leaf Node ")
            print("Value is: ", node.value)
            print("Content is: ", node.content)
            print()
        
        else:
            print("Non-leaf node ")
            print("Value is: ", node.value)
            print("Content is: ", node.content)
            print()
            self.__printTreeRec(node.left)
            self.__printTreeRec(node.right)
        
 
    #return the root Node object
    def getRoot(self):
      return self.root


    #find path from root to given Node
    def findPath(self, root: Node, x: Node, arr: list = []):
        if (not root):
            return False
     
        # push the node's value in 'arr'
        arr.append(root)    
        if (root == x):    
            return True
        if (self.findPath(root.left, x, arr) or
            self.findPath(root.right, x, arr)):
            return True
  
        arr.pop(-1)
        return False
    

    #find siblingPath
    def siblingPath(self, path: list[Node]):
        siblingPath  = []
        for index, elem in enumerate(path):
            if elem.value == self.root.value:
                siblingPath.append(elem)
            else:
                parent = path[index-1]
                if elem.value == parent.left.value:
                    siblingPath.append(parent.right)
                elif elem.value == parent.right.value:
                    siblingPath.append(parent.left)
                else:
                    print("error")

        return siblingPath
    
    #Ffind Node
    def findNode(self, node: Node, val: str):
        if node == None:
            return None
        if node.value == val:
            return node
        else:
            ans1 = self.findNode(node.left, val)
            if ans1:
                return ans1
            ans2 = self.findNode(node.right, val)
            if ans2:
                return ans2
            
        return None


#Hash a file
def hashFile(filename):
    with open(filename, 'rb') as f:
        data = f.read()
        sha256hash = sha256(data).hexdigest()
    f.close()
    return sha256hash


#Encrypt a file with a given key
def encrypt(inputFileName, key):
    
    inputFile = open(inputFileName, 'rb')
    outputFile = open(inputFileName + '.encrypted', 'wb')

    iv = "0000000000000000"
    cipherEncrypt = AES.new(key, AES.MODE_CFB, iv.encode("utf8"))

    buffer = inputFile.read(bufferSize)
    
    while len(buffer) > 0:
        cipheredBytes = cipherEncrypt.encrypt(buffer)
        outputFile.write(cipheredBytes)
        buffer = inputFile.read(bufferSize)

    # Close the input and output files
    inputFile.close()
    outputFile.close()

    return


#Decrypt a file with a given key
def decrypt(inputFileName, key):

    inputFile = open(inputFileName + '.encrypted', 'rb')
    outputFile = open(inputFileName + '.decrypted', 'wb')
    iv = "0000000000000000"
    # Create the cipher object and encrypt the data
    cipher_encrypt = AES.new(key, AES.MODE_CFB, iv.encode("utf8"))

    # Keep reading the file into the buffer, decrypting then writing to the new file
    buffer = inputFile.read(bufferSize)
    while len(buffer) > 0:
        decrypted_bytes = cipher_encrypt.decrypt(buffer)
        outputFile.write(decrypted_bytes)
        buffer = inputFile.read(bufferSize)

    # Close the input and output files
    inputFile.close()
    outputFile.close()

    return


#Create DTag
def createDTag(hashFile):
    DTag = hex(eval((bin(eval("0x"+hashFile)))[:-2]))[2:]
    return DTag


#Create Ftag
def createFTag(filename):
    FTag =  hashFile(filename + '.encrypted')
    return FTag


#Encrypt Key
def encryptKey(key, filename):
    blocks = createBlocks(filename)
    MT = MerkleTree(blocks)
    rootNode = MT.getRoot()
    leaves = MT.getLeaves()
    sizeOfL = int(log(len(leaves), 2))
    L = random.sample(leaves, sizeOfL)
    S = []
    Lreturn = []
    for leaf in L: 
        path=[]
        temp = []
        MT.findPath(rootNode, leaf, path)
        siblings = MT.siblingPath(path)
        xOrResult = int("0x"+siblings[0].value, 16)
        temp.append(xOrResult)
        for elem in siblings[1:]:
            hexStringToInt = int("0x"+elem.value, 16)
            temp.append(hexStringToInt)
            xOrResult ^= hexStringToInt

        S.append(xOrResult)   
        Lreturn.append(leaf.value)
    key = int((key),16)
    CKey  = key
    for elem in S:
        CKey ^= elem
    #return CKey as hex str
    CKey = hex(CKey)[2:]

    return CKey, Lreturn


#Create blocks from file
def createBlocks(filename):
    with open(filename) as f:
        block = f.read(64)
        blocks = []
        while block:
            blocks.append(block)
            block = f.read(64)
    f.close()
    return blocks


#Check if DTag is present in server
def checkifDTagPresent(DTag):
    docs=db.collection('persons').where("DTag","==",DTag).get()
    startDedupTime = time()
    if(len(docs)==0):
        endDedupTime = time()
        print("VerifyDedupTimeNotPresent: ", endDedupTime-startDedupTime)   
        return (False, None, None, None, None, None)
    else:
        doc_ref = db.collection('persons').where("DTag","==",DTag)
        #Decrypt all CKeys
        FTags = []
        CKeys = []
        Ls = []
        R = secrets.token_hex(32)
        clients = []

        Lfile = DTag+"L.txt"

        for doc in doc_ref.stream():
            FTags.append(doc.to_dict()['FTag'])
            clients.append(doc.to_dict()['client'])
            if 'CKey' in doc.to_dict():
                CKeys.append(doc.to_dict()['CKey'])
            
            
        storage.child(Lfile).download(Lfile, Lfile)

        with open(Lfile) as f:
            reader = csv.reader(f)
            for row in reader:
                Ls.append(row)
        f.close()
        endDedupTime = time()
        print("VerifyDedupTimePresent: ", endDedupTime-startDedupTime)
        return (True, CKeys, FTags, Ls, clients, R)


#LearnKey function
def learnKey(CKeys: list, FTags: list, Ls: list, filename):
    blocks = createBlocks(filename)
    MT = MerkleTree(blocks)
    rootNode = MT.getRoot()
    leaves = MT.getLeaves()
    siblings = []
    key = []
    # CFile = []
    FTag = []
    L = []

    for elem in Ls:
        temp = []
        for e in elem:
            temp.append(MT.findNode(rootNode, e))
        L.append(temp)
    
    Ls = L

    for i in range(len(CKeys)):
        S = []
        for j in range(len(Ls[i])):
            path = []
            MT.findPath(rootNode, Ls[i][j], path)
            siblings = MT.siblingPath(path)
            temp1 = int("0x"+siblings[0].value, 16)
            for elem in siblings[1:]:
                hexStringToInt = int("0x"+elem.value, 16)
                temp1 ^= hexStringToInt
            S.append(temp1)

        STemp = int("0x"+CKeys[i], 16)
        for elem in S:
            STemp ^= elem

        key.append(hex(STemp)[2:])
        encrypt(filename, bytearray.fromhex(key[i]))
        FTag.append(createFTag(filename))
        if FTag[i] == FTags[i]:
            return key[i]   
            
    return None


#SUpload function
def SUpload(DTag: int, FTag: int, newCFile: int, FTags: list):
    #if FTag in FTags[DTag]:
    #FILEOWERS thing
    # serverFileName = 
    if FTag in FTags:
        index = FTags.index(FTag)
        serverFilename = clients[index] 
        storage.child(serverFilename).download('down'+serverFilename,'down'+serverFilename)
        if hash(randomCFile('down'+serverFilename, R)) == newCFile:
            coll_ref = db.collection("persons")
            create_time, doc_ref = coll_ref.add({'DTag':DTag,'FTag':FTag, 'client':filename+'.encrypted'})  
            return True 
        
    return False


#RandomCFile
def randomCFile(fileName, R):
    file = open(fileName, 'a')
    file.write(R)
    file.close()
    return


#Main function
if __name__ == '__main__':

    #firebase
    cred = credentials.Certificate("serviceAccountKey.json")
    firebase_admin.initialize_app(cred)

    db=firestore.client()

    firebaseConfig={'apiKey': "AIzaSyBr_SbOpf6QgnEJq55BJRS2uhRiQagbD7E",
    'authDomain': "cloud-817e4.firebaseapp.com",
    'projectId': "cloud-817e4",
    'storageBucket': "cloud-817e4.appspot.com",
    'messagingSenderId': "626556138355",
    'appId': "1:626556138355:web:7a1a945001cda0fbfe0b06",
    'measurementId': "G-ZPNEEF8FKV",
    'databaseURL':""}

    firebase=pyrebase.initialize_app(firebaseConfig)
    
    storage=firebase.storage()

    filename = "4KB.txt"
    bufferSize = 65536

    #Total Time
    startTotalTime = time()

    #Hash(file)
    sha256hash = hashFile(filename)

    #3/4/2022
    '''1. The client sends DTag (first 254 bits of Hash(File)).'''

    DTag = createDTag(sha256hash)

    '''2. Server replies (FALSE, {}, {}, {}) if DTag does not exist.'''
    filePresent, CKeys, FTags, Ls, clients, R = checkifDTagPresent(DTag) 

    #Check for presence of file in server
    if not filePresent:
        print("FALSE")

        startFileEncryptTime = time()
        #Encrypt File using random key anf generate CFile
        randomEncryptionKey = secrets.token_hex(32)
        encrypt(filename, bytearray.fromhex(randomEncryptionKey))
        endFileEncryptTime = time()
        print("File Encryption Time: ", endFileEncryptTime-startFileEncryptTime)  

        #4. Encrypt key using sibling path and compute FTag
        FTag = createFTag(filename)

        startKeyEncTime = time()
        CKey, Ls = encryptKey(randomEncryptionKey, filename)
        endKeyEncTime = time()
        print("Key Encryption Time: ", endKeyEncTime-startKeyEncTime)

        #upload (DTag, FTag, CFile, CKey, {L})
        #Create a file for L
        Lfile = DTag + "L.txt"
        with open(Lfile, 'w') as f:
            csv.writer(f).writerow(Ls)
        f.close()
        
        storage.child(Lfile).put(Lfile)
        storage.child(filename+'.encrypted').put(filename+'.encrypted')
        coll_ref = db.collection("persons")
        create_time, doc_ref = coll_ref.add({'DTag':DTag,'FTag':FTag,'CKey':CKey, 'client':filename+'.encrypted'})

        print("File uploaded successfully")
        # print("DTAG ",DTag)
        # print("FTAG ",FTag)
        # print("CKEY ",CKey)
        # print("Ls ",Ls)
    
    else:
        print("TRUE")

        '''3.a. Client decrypts all CKeys one by one, encrypts the file using Key[i],
            compute hash of encrypted file, and matches it with FTag[i]. 
            If matching, it is the key used by first uploader. 
            Client stores the key in its local storage. 
            Client sends (DTag, FTag) to the server. Server adds client in owners' list of FTag.'''
        
        #if same Dtag is found on server.This needs to be completed.
        #Encrypt file using CKey[i]
        startLearnKeyTime = time()
        key= learnKey(CKeys, FTags, Ls, filename)
        endLearnKeyTime = time()
        print("LearnKey Time: ", endLearnKeyTime-startLearnKeyTime)

        if key:
            print("in key")
            encrypt(filename, bytearray.fromhex(key))
            FTag = createFTag(filename)

            if SUpload(DTag, FTag, hash(randomCFile(filename+".encrypted", R)), FTags) == True:
                print("TRUE")

            else:
                print("NEW PART")
                startFileEncryptTime = time()
                #Encrypt File using random key anf generate CFile
                randomEncryptionKey = secrets.token_hex(32)
                encrypt(filename, bytearray.fromhex(randomEncryptionKey))
                endFileEncryptTime = time()
                print("File Encryption Time: ", endFileEncryptTime-startFileEncryptTime)  

                #4. Encrypt key using sibling path and compute FTag
                FTag = createFTag(filename)

                startKeyEncTime = time()
                CKey, Ls = encryptKey(randomEncryptionKey, filename)
                endKeyEncTime = time()
                print("Key Encryption Time: ", endKeyEncTime-startKeyEncTime)

                #upload (DTag, FTag, CFile, CKey, {L})
                #Create a file for L
                Lfile = DTag + "L.txt"
                with open(Lfile, 'w') as f:
                    csv.writer(f).writerow(Ls)
                f.close()
                
                storage.child(Lfile).put(Lfile)
                storage.child(filename+'.encrypted').put(filename+'.encrypted')
                coll_ref = db.collection("persons")
                create_time, doc_ref = coll_ref.add({'DTag':DTag,'FTag':FTag,'CKey':CKey})

                print("File uploaded successfully")



    endtTotalTime = time()
    print("Total time ",endtTotalTime-startTotalTime) 
