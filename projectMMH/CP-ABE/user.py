from Include import auth as a
from Include import TLSclient as TLS
# import hashlib
import pyfiglet
import json
import os


def main():
    try:
        banner = pyfiglet.figlet_format("Hospital Database")
        print(banner)

        # Xác thực database chứa thông tin login của user
        auth = a.auth() 
        print("Please select an option:")
        print("1. Log in")
        print("2. Sign up")
        print("3. Quit")
        choice = input('Enter your choice: ')
        try:
            # Xác thực người dùng
            if choice == '1':
                id = auth.login()
            elif choice == '2':
                id = auth.signup()
            else:
                print('Invalid choice')
                exit(1)
        except:
            print("Good bye!")
            return
        
        if type(id) != str:
            print("Good bye!")
            return
    except Exception as e:
        print(f'exception of user.py: {e}')
        print("You do not have access")
        exit(1)
    except KeyboardInterrupt:
        print('\nUser stopped')
        exit(1)
        # User yêu cầu bản PHR tương ứng
def phrdetails(request,id):
        auth = a.auth() 
        
        #Tải ciphertext từ cloud
        ciphertextName = "phr" + request + ".json.crypt"
        cipherImgName = 'phr' + request + '.png.crypt'
        print('Retrieving encrypted file...')
        auth.Retrieve_cipher(request)

        #Kết nối với Trusted Authority và tiến hành giải mã
        print('Connecting to Trusted Authority Server...')
        connect = TLS.client()
        plt, policy = connect.connect_returnPlt(auth.authenticate_user(id), request, ciphertextName)
        if os.path.exists(cipherImgName):
            img, policy = connect.connect_returnPlt(auth.authenticate_user(id), request, cipherImgName)
            
        os.system("rm " + ciphertextName)
        
        
        if plt:    
            #Ghi nội dung JSON vào file
            print("Policy: " , policy)
            json_str = plt.decode('utf-8')
            with open(ciphertextName[:-6], 'w') as json_file:
                json.dump(json.loads(json_str), json_file, indent=4);
            print(f"The plaintext has been exported to the file {ciphertextName[:-6]}")
            if os.path.exists(cipherImgName):
                with open(cipherImgName[:-6], 'wb') as img_file:
                    img_file.write(img)
                os.system("rm " + cipherImgName)
                
            return True
        else:
            return False
    

    
if __name__=="__main__":
    main()