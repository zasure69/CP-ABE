import sys
sys.path.append("/home/skyd214/Documents/MMH/project/Project-MMH-CP-ABE/CP-ABE/Include")
import phr as cp_abe
import Transform as Serialize
import TLSclient
# from Crypto.Util.number import bytes_to_long,long_to_bytes

import pymongo as mdb
import json
import socket
import base64
import ssl
import os
import certifi
import re

class DataOwner:
    
    myclient = mdb.MongoClient(
    "mongodb+srv://22520415:u6nBvR4Mx7mfsENV@mmh.yzt5r4z.mongodb.net/?retryWrites=true&w=majority&appName=MMH", 
    tls=True, 
    tlsCAFile=certifi.where(),
    tlsAllowInvalidCertificates=False,
    )
    mydb = myclient['mmh']

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

    def addphr(self,fileName,fileImage,idowner):
        print("You choose to add a new PHR.")
        # Kết nối đến máy chủ đích
        HOST = '127.0.0.1'
        PORT = 8000
        #certificate
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        context.load_verify_locations('../CP-ABE/server.crt')

        with socket.create_connection((HOST, PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as owner_socket:

                #Nhập tên file và lấy index
                mycol = self.mydb['ciphertext']
                docs = list(mycol.find())
                count = len(docs)
                col = self.mydb['user']
                doc = mycol.find_one({'_id': idowner})

                #Đọc file
                sourcefile = open(fileName, 'rb')
                msg = sourcefile.read()
                sourcefile.close()
                msg_dict = json.loads(msg)

                index = msg_dict["ID"]
                owner_socket.sendall(index.encode('utf-8'))
                #Lấy thuộc tính và policy
                policy = '(' + idowner + ' or ' + msg_dict["ID"] + ' or ' 
                for item in msg_dict['NGUOIPHUTRACH']:
                    if msg_dict['NGUOIPHUTRACH'][-1] != item:
                        policy += "(" + item['ID'] + ' and ' + item['khoa'].upper() + ")" + " or "
                    else:
                        policy += "(" + item['ID'] + ' and ' + item['khoa'].upper() + ")" + ')'
                #Chuẩn bị gửi khóa đến Trusted Authority
                print("Sent to server....")

                #Tạo pk, msk và ciphertext
                abe = cp_abe.ABE()
                key = Serialize.Transform()
                pk, mk = abe.setup()
                if fileImage and os.path.exists(fileImage):
                    cipherimg = abe.encrypt(pk, fileImage, policy, 0)
                try:
                    cipher = abe.encrypt(pk, fileName, policy, 0)
                except Exception as e:
                    print("encrypt error: ", e)
                #Gửi pk và msk đến Trusted Authority
                pk_bytes = key.jsonify_pk(pk)
                pk_bytes = base64.b64encode(pk_bytes.encode())
                mk_bytes = key.jsonify_mk(mk)
                mk_bytes = base64.b64encode(mk_bytes.encode())
                print("len pk_bytes: ", len(pk_bytes))
                print("len mk_bytes: ", len(mk_bytes))
                print("len mk + pk: ", len(pk_bytes) + len(mk_bytes))
                owner_socket.sendall(pk_bytes+mk_bytes)
                if fileImage and os.path.exists(fileImage):
                #Gửi ciphertext lên cloud
                    cipher_data = {
                        'patientid': msg_dict['ID'],
                        'data': cipher,
                        'dataimg': cipherimg
                    }
                else:
                    cipher_data = {
                        'patientid': msg_dict['ID'],
                        'data': cipher,
                        'dataimg': ''
                    }
                
                x = mycol.insert_one(cipher_data)
                print("Add successfully!")
                owner_socket.close()
                return True

    def revoatt(self,phrId,id,idowner):
        id = id.split(" ")
        mycol = self.mydb['user']
        docs = mycol.find_one({"_id": idowner})
        revoke_data = docs['revokeduser']
        if phrId in revoke_data.keys():
            if id not in revoke_data[phrId]:
                for i in id:
                    if i not in revoke_data[phrId]:
                        revoke_data[phrId].append(i)
        else:
            revoke_data[phrId] = id
        x = mycol.update_one({"_id": idowner}, {"$set": {"revokeduser": revoke_data}})
        self.Retrieve_cipher(phrId)
        connect = TLSclient.client()
        plt, pol = connect.connect_returnPlt(docs, phrId, 'phr' + phrId + '.json.crypt')
        if os.path.exists('phr' + phrId + '.png.crypt'):
            img, pol = connect.connect_returnPlt(docs, phrId, 'phr' + phrId + '.png.crypt')
            
        # pattern = r'\b(US\d{3}|BS\d{3}|BN\d{3})\b'
        # ids = re.findall(pattern, str(pol)) # list
        pol = str(pol)
        os.system("rm " + 'phr' + phrId + '.json.crypt')
        
        print("Plt", plt)
        if plt:
            json_str = plt.decode('utf-8')
        else:
            return False
        # Kết nối đến máy chủ đích
        HOST = '127.0.0.1'
        PORT = 8000
        #certificate
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        context.load_verify_locations('../CP-ABE/server.crt')
        with socket.create_connection((HOST, PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as owner_socket:
                col = self.mydb['user']
                docs = list(col.find())
                col1 = self.mydb['ciphertext']
                doc = col.find_one({'_id': idowner})
                revokeduser = doc['revokeduser'][phrId]
                #Đọc file
                msg_dict = json.loads(json_str)

                index = msg_dict["ID"]
                owner_socket.sendall(index.encode('utf-8'))
                #Lấy thuộc tính và policy
                print(pol)
                for user in id:
                # Nếu ID là BSXXX, xóa cả phần "and XXXXXX" nếu có và các toán tử, dấu ngoặc liên quan
                    if user.startswith("BS"):
                        pattern = fr'\(\s*{user} and \w+\s*\)'
                    else:
                        pattern = fr'\b{user}\b'
                    
                    pol = re.sub(pattern, '', pol)

                # Xóa các từ khóa "or" hoặc "and" thừa và dọn dẹp các dấu ngoặc
                # Xử lý các dấu ngoặc thừa sau khi loại bỏ các ID
                pol = re.sub(r'\(\s*or\s*\)', '', pol)
                pol = re.sub(r'\(\s*and\s*\)', '', pol)
                pol = re.sub(r'\(\s*\)', '', pol)
                pol = re.sub(r'\s+', ' ', pol).strip()

                # Xóa các toán tử thừa ở đầu hoặc cuối chuỗi
                pol = re.sub(r'^\s*or\s*', '', pol)
                pol = re.sub(r'\s*or\s*$', '', pol)
                pol = re.sub(r'^\s*and\s*', '', pol)
                pol = re.sub(r'\s*and\s*$', '', pol)

                # Xóa các từ khóa "or" hoặc "and" thừa trước dấu ngoặc đóng và sau dấu ngoặc mở
                pol = re.sub(r'\s*or\s*\)', ')', pol)
                pol = re.sub(r'\(\s*or\s*', '(', pol)
                pol = re.sub(r'\s*and\s*\)', ')', pol)
                pol = re.sub(r'\(\s*and\s*', '(', pol)

                # Chuẩn hóa chuỗi policy cuối cùng
                pol = re.sub(r'\(\s*', '(', pol)
                pol = re.sub(r'\s*\)', ')', pol)
                pol = re.sub(r'\s+', ' ', pol).strip()

                # Đảm bảo các dấu ngoặc bao quanh chuỗi, nếu cần
                if not (pol.startswith('(') and pol.endswith(')')):
                    pol = f"({pol})"
                
                print(pol)
                        
                #Chuẩn bị gửi khóa đến Trusted Authority
                print("Sent to server....")
                #Tạo pk, msk và ciphertext
                abe = cp_abe.ABE()
                key = Serialize.Transform()
                pk, mk = abe.setup()
                if os.path.exists('phr' + phrId + '.png.crypt'):
                    print(type(img))
                    cipherimg = abe.encrypt(pk, img,  pol, 1)
                try:
                    cipher = abe.encrypt(pk, json.dumps(msg_dict).encode('utf-8'),  pol, 1)
                    # os.system('rm data_decrypt.json')
                    
                except Exception as e:
                    print("encrypt error: ", e)
                #Gửi pk và msk đến Trusted Authority
                pk_bytes = key.jsonify_pk(pk)
                pk_bytes = base64.b64encode(pk_bytes.encode())
                print(len(pk_bytes))
                mk_bytes = key.jsonify_mk(mk)
                mk_bytes = base64.b64encode(mk_bytes.encode())
                print(len(mk_bytes))
                owner_socket.sendall(pk_bytes+mk_bytes)
                
                #Gửi ciphertext lên cloud
                if os.path.exists('phr' + phrId + '.png.crypt'):
                    x = col1.update_one({"patientid": msg_dict['ID']}, {'$set': {'data': cipher, 'dataimg': cipherimg}})
                    os.system("rm " + 'phr' + phrId + '.png.crypt')
                else:
                    x = col1.update_one({"patientid": msg_dict['ID']}, {'$set': {'data': cipher, 'dataimg': ''}})
                
                print("Update successfully!")
                owner_socket.close()
                return True
    def updphr(self,phrId,fileName,idowner): 
        # Kết nối đến máy chủ đích
        HOST = '127.0.0.1'
        PORT = 8000
        #certificate
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        context.load_verify_locations('../CP-ABE/server.crt')
        mycol = self.mydb['user']
        docs = mycol.find_one({"_id": idowner})
        self.Retrieve_cipher(phrId)
        os.system('rm ' + 'phr' + phrId + '.json.crypt')
        connect = TLSclient.client()
        if os.path.exists('phr' + phrId + '.png.crypt'):
            
            img, pol = connect.connect_returnPlt(docs, phrId, 'phr' + phrId + '.png.crypt')
        with socket.create_connection((HOST, PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as owner_socket:
                col1 = self.mydb['ciphertext']
                col = self.mydb['user']
                doc = col.find_one({'_id': idowner})
                revoke_data = doc['revokeduser']
                if phrId in revoke_data.keys():
                    revoke_data[phrId] = []
                    x = col.update_one({"_id": idowner}, {"$set": {"revokeduser": revoke_data}})
                self.Retrieve_cipher(phrId)
                #Đọc file
                sourcefile = open(fileName, 'rb')
                msg = sourcefile.read()
                sourcefile.close()
                msg_dict = json.loads(msg)

                index = msg_dict["ID"]
                if index != phrId:
                    return False
                owner_socket.sendall(index.encode('utf-8'))
                #Lấy thuộc tính và policy
                policy = '((' + idowner + ') or (' + msg_dict["ID"] + ') or ' 
                for item in msg_dict['NGUOIPHUTRACH']:
                    if msg_dict['NGUOIPHUTRACH'][-1] != item:
                        policy += "(" + item['ID'] + ' and ' + item['khoa'].upper() + ")" + " or "
                    else:
                        policy += "(" + item['ID'] + ' and ' + item['khoa'].upper() + ")" + ')'
                
                print("Policy 3: ", policy)
                #Chuẩn bị gửi khóa đến Trusted Authority
                print("Sent to server....")
                
                #Tạo pk, msk và ciphertext
                abe = cp_abe.ABE()
                key = Serialize.Transform()
                pk, mk = abe.setup()
                if os.path.exists('phr' + phrId + '.png.crypt'):
                    print(type(img))
                    cipherimg = abe.encrypt(pk, img,  policy, 1)
                try:
                    cipher = abe.encrypt(pk, fileName, policy, 0)
                except Exception as e:
                    print("encrypt error: ", e)
                    return False
                #Gửi pk và msk đến Trusted Authority
                pk_bytes = key.jsonify_pk(pk)
                pk_bytes = base64.b64encode(pk_bytes.encode())
                mk_bytes = key.jsonify_mk(mk)
                mk_bytes = base64.b64encode(mk_bytes.encode())
                print("len pk_bytes: ", len(pk_bytes))
                print("len mk_bytes: ", len(mk_bytes))
                print("len mk + pk: ", len(pk_bytes) + len(mk_bytes))
                owner_socket.sendall(pk_bytes+mk_bytes)
                
                # x = col1.update_one({"patientid": phrId}, {'$set': {'data': cipher}})
                #Gửi ciphertext lên cloud
                if os.path.exists('phr' + phrId + '.png.crypt'):
                    x = col1.update_one({"patientid": msg_dict['ID']}, {'$set': {'data': cipher, 'dataimg': cipherimg}})
                    os.system("rm " + 'phr' + phrId + '.png.crypt')
                else:
                    x = col1.update_one({"patientid": msg_dict['ID']}, {'$set': {'data': cipher, 'dataimg': ''}})
                print("Update successfully!")
                owner_socket.close()
                return True
                    
    def updpoli(self,phrId,id,idowner):
        id = id.split(" ")
        mycol = self.mydb['user']
        docs = mycol.find_one({"_id": idowner})
        revoke_data = docs['revokeduser']
        if phrId in revoke_data.keys():
            for i in id:
                if i in revoke_data[phrId]:
                    revoke_data[phrId].remove(i)
            x = mycol.update_one({"_id": idowner}, {"$set": {"revokeduser": revoke_data}})
        self.Retrieve_cipher(phrId)
        connect = TLSclient.client()
        plt, policy = connect.connect_returnPlt(docs, phrId, 'phr' + phrId + '.json.crypt')
        if os.path.exists('phr' + phrId + '.png.crypt'):
            img, pol = connect.connect_returnPlt(docs, phrId, 'phr' + phrId + '.png.crypt')
            
        pattern = r'\b(US\d{3}|BS\d{3}|BN\d{3})\b'
        ids = re.findall(pattern, str(policy)) # list
        policy = str(policy)
        os.system("rm " + 'phr' + phrId + '.json.crypt')
        print("Plt", plt)
        if plt:
            json_str = plt.decode('utf-8')
        else: 
            return False
        # Kết nối đến máy chủ đích
        HOST = '127.0.0.1'
        PORT = 8000
        #certificate
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False
        context.load_verify_locations('../CP-ABE/server.crt')
        with socket.create_connection((HOST, PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=HOST) as owner_socket:
                col = self.mydb['user']
                docs = list(col.find())
                col1 = self.mydb['ciphertext']
                doc = col.find_one({'_id': idowner})
                if phrId in doc['revokeduser'].keys():
                    
                    revokeduser = doc['revokeduser'][phrId]
                else:
                    revokeduser = []
                #Đọc file
                msg_dict = json.loads(json_str)

                index = msg_dict["ID"]
                owner_socket.sendall(index.encode('utf-8'))
                #Lấy thuộc tính và policy
                
                # l = []
                # for i in msg_dict['NGUOIPHUTRACH']:
                #     l.append(i['ID'])
                flag = 1
                for i in range(0, len(id)):
                    if (i % 2) == 0 and id[i] not in ids:
                        flag = 0
                if (flag == 0):
                    policy = policy[:-1]
                for i in range(0, len(id)):
                    if id[i] not in ids:
                        if 'BS' not in id[i]:
                            policy += ' or (' + id[i] + ')'
                        else:
                            d = col.find_one({'_id': id[i]})
                            policy += ' or (' + id[i] + ' and ' + d['faculty'] + ')'
                if (flag == 0):
                    policy += ')'
                print("Policy 4: ", policy)
                #Chuẩn bị gửi khóa đến Trusted Authority
                print("Sent to server....")
                #Tạo pk, msk và ciphertext
                abe = cp_abe.ABE()
                key = Serialize.Transform()
                pk, mk = abe.setup()
                if os.path.exists('phr' + phrId + '.png.crypt'):
                    print(type(img))
                    cipherimg = abe.encrypt(pk, img,  policy, 1)
                try:
                    cipher = abe.encrypt(pk, json.dumps(msg_dict).encode('utf-8'),  policy, 1)
                
                except Exception as e:
                    print("encrypt error: ", e)
                #Gửi pk và msk đến Trusted Authority
                pk_bytes = key.jsonify_pk(pk)
                pk_bytes = base64.b64encode(pk_bytes.encode())
                print(len(pk_bytes))
                mk_bytes = key.jsonify_mk(mk)
                mk_bytes = base64.b64encode(mk_bytes.encode())
                print(len(mk_bytes))
                owner_socket.sendall(pk_bytes+mk_bytes)
                
                #Gửi ciphertext lên cloud
                if os.path.exists('phr' + phrId + '.png.crypt'):
                    x = col1.update_one({"patientid": msg_dict['ID']}, {'$set': {'data': cipher, 'dataimg': cipherimg}})
                    os.system("rm " + 'phr' + phrId + '.png.crypt')
                else:
                    x = col1.update_one({"patientid": msg_dict['ID']}, {'$set': {'data': cipher, 'dataimg': ''}})
                
                print("Update successfully!")
                owner_socket.close()
                return True