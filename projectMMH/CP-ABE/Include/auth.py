import sys
sys.path.append("/home/skyd214/Documents/MMH/project/Project-MMH-CP-ABE/CP-ABE/Include")
# import DataOwner as DO
import pyrebase
import hashlib
# import getpass
import pymongo as mdb
import certifi
import ssl

class auth:
    myclient = mdb.MongoClient(
    "mongodb+srv://22520415:u6nBvR4Mx7mfsENV@mmh.yzt5r4z.mongodb.net/?retryWrites=true&w=majority&appName=MMH", 
    tls=True, 
    tlsCAFile=certifi.where(),
    tlsAllowInvalidCertificates=False,
    )
    mydb = myclient['mmh']

    # Hàm xác thực người dùng
    def authenticate_user(self, id):
        mycol = self.mydb['user']
        user = mycol.find_one({'_id': id})
        if len(user):
            return user
        # Nếu không xác thực được, trả về None
        return None
    # Hàm login
    def login(self, email, password):
        try:
            mycol = self.mydb['user']

            mydoc = list(mycol.find({'email': email}))
            if len(mydoc):
                if hashlib.sha256(password.encode()).hexdigest() == mydoc[0]['password']:
                    return mydoc[0]['_id']
            else:
                print('Email is not exists')
                return False
        except Exception as e:
            print(f"error login: {e}")
            print("Invalid email or password")
            return False
        
    #Hàm signup
    def signup(self, email, password, citizenId, role):
        try:
            mycol = self.mydb['user']
            mydoc = list(mycol.find())
            if len(mydoc) == 0:
                print('null')
                id = "US001"
            else:
                tmp = 3 - len(str(len(mydoc)  + 1))
                id = "US"
                for i in range(0, tmp):
                    id += '0'
                id = id + str(len(mydoc) + 1)
            user_data = {
                '_id': id, 
                'email': email, 
                'password': hashlib.sha256(password.encode()).hexdigest(),
                'citizenid': citizenId, 
                'role': 'user'
            }
            x = mycol.insert_one(user_data)
            print("Successfully signed up!")
        except Exception as e:
            print(e)
            print("Invalid email or password")
            return
    
    # Lấy ciphertext từ Cloud
    def Retrieve_cipher(self, filename):
        ciphercol = self.mydb['ciphertext']
        doc = ciphercol.find_one({'patientid': filename})

        # Lấy nội dung của tệp từ document
        try:
            file_content = doc['data']
            cipherfile = open('phr' + filename + '.json.crypt', 'wb')
            cipherfile.write(file_content)
            cipherfile.close()
            file_content1 = doc['dataimg']
            if file_content1:
                cipherfile1 = open('phr' + filename + '.png.crypt', 'wb')
                cipherfile1.write(file_content1)
                cipherfile1.close()
            print("Download encryption successful!")
        except Exception as e:
            print(f'error in retrieve cipher: {e}')
            print("Download encryption Failed!")
            return False
