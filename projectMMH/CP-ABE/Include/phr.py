from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.core.engine.util import *
from charm.schemes.abenc.ac17 import AC17CPABE
import sys
sys.path.append("/home/skyd214/Documents/MMH/project/Project-MMH-CP-ABE/CP-ABE/Include")
import Transform as trans
from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import hashlib 
import struct

class ABE:
    def __init__(self):
        self.groupObj = PairingGroup('SS512')
        self.cpabe = AC17CPABE(self.groupObj, 3)
        
    # pk, msk
    def setup(self):
        (pk, msk) = self.cpabe.setup()
        return pk, msk
     
    # sk
    def keygen(self, pk, msk, attr_list):
        sk = self.cpabe.keygen(pk, msk, attr_list)
        return sk
        
    # encrypt msg
    def encrypt(self, pk, filename, policy, m):
        if m == 0:
            file = open(filename, 'rb')
            msg = file.read()
            file.close()
        elif m == 1:
            msg = filename
        Trans_enc = trans.Transform()
        key = self.groupObj.random(GT)

        try:
            encrypt_cpabe = self.cpabe.encrypt(pk, key, policy) # {'policy': policy, 'C_0': C_0, 'C': C, 'Cp': Cp}
        except Exception as e:
            print("encrypt_cpabe error", e)
        
        nonce = get_random_bytes(16)
        
        encrypt_key = hashlib.shake_256(str(key).encode()).digest(32)
        cipher = AES.new(encrypt_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(msg) # tag = 16
        
        #struct.pack
        json_encrypt = Trans_enc.jsonify_ctxt(encrypt_cpabe)
        json_encrypt = b64encode(json_encrypt.encode("utf-8"))
        json_length = len(json_encrypt)
        struct_pack = struct.pack('Q', json_length) # 8
        
        return struct_pack + nonce + tag + json_encrypt + ciphertext
        
    
    def decrypt(self, pk, filename, skey):
        Trans_enc = trans.Transform()
        
        ciphertext_file = open(filename, 'rb')
        json_length = struct.unpack('Q',ciphertext_file.read(struct.calcsize('Q')))[0]
        ciphertext_file.close()
        
        ciphertext = open(filename,"rb").read()
        
        nonce = ciphertext[8:24]
        tag = ciphertext[24:40]
        json_encrypt = ciphertext[40:json_length + 40]
        json_encrypt = b64decode(json_encrypt.decode("utf-8"))
        json_encrypt = Trans_enc.unjsonify_ctxt(json_encrypt)
        
        key = self.cpabe.decrypt(pk, json_encrypt, skey)
        if key:
            encrypt_key = hashlib.shake_256(str(key).encode()).digest(32)
            decipher = AES.new(encrypt_key, AES.MODE_GCM, nonce=nonce)
            plaintext = decipher.decrypt_and_verify(ciphertext[40 + json_length:], tag)
            return plaintext, json_encrypt['policy']
        else:
            return "", json_encrypt['policy']
        
        
        