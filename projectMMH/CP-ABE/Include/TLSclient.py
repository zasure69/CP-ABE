import sys
sys.path.append("/home/skyd214/Documents/MMH/project/Project-MMH-CP-ABE/CP-ABE/Include")
import Transform as Serialize
import phr as cp_abe
import socket
import ssl
import json
import base64

class client:
    # Khởi tạo kết nối ssl giữa người dùng và CA
    def connect_returnPlt(self, json_data, request, ciphertextName):
        try:
            HOST = '127.0.0.1'
            PORT = 62345
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = False
            context.load_verify_locations('../CP-ABE/server.crt')
            print("1")
            #Thiết lập kết nối
            with socket.create_connection((HOST, PORT)) as sock:
                with context.wrap_socket(sock, server_hostname=HOST) as client_socket:
                    print("1")
                    #Tạo dữ liệu và gửi đi
                    json_data["request"] = request
                    json_str = json.dumps(json_data)
                    client_socket.sendall(json_str.encode('utf-8'))
                    key = Serialize.Transform()

                    # Nhận phản hồi
                    response = ''
                    while True:
                        try:
                            data = client_socket.recv(1024)
                            response += data.decode('utf-8')
                            if len(data) < 1024:
                                break
                        except socket.timeout:
                            print('Timeout occurred')
                            break
                    print("2")
                    #Tách bytes 
                    response1 = response[:1244]
                    response2 = response[1244:]

                    #Lấy pk
                    pk_bytes = base64.b64decode(response1)
                    pk = key.unjsonify_pk(pk_bytes)

                    #Lấy sk
                    sk_bytes = base64.b64decode(response2)
                    sk = key.unjsonify_sk(sk_bytes)
                    print("3")
                    # Đóng kết nối
                    client_socket.close()

                    #Giải mã
                    print('Decrypting file...')
                    abe = cp_abe.ABE()
                    try:
                        plt, policy = abe.decrypt(pk, ciphertextName, sk)
                        # if self.check_attributes()
                        # if plt == "":
                        #     return "", policy
                        # else:
                        return plt, policy
                    except Exception as e:
                        print('error in decrypt ', e)
                    
        except Exception as e:
            print(f'error in  connect_returnTLS {e}')
            print("ERROR")
            return None
    
    def check_attributes(self, user_attributes, policy):
        # Kiểm tra thuộc tính của người dùng có thỏa mãn chính sách hay không.
        for attr in policy:
            if attr not in user_attributes:
                return False
        return True