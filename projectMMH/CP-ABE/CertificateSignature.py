from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID
import datetime

class signature:
    def Self_signed_certificate(self):
        # Tạo một cặp khóa ECC với đường cong prime256v1
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"VN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"TPHCM"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"TP Thu Duc"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UIT"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"127.0.0.1"),
        ])


        # Tạo chứng chỉ x509 tự ký
        cert = x509.CertificateBuilder().subject_name(
            subject
                    ).issuer_name(
                        issuer
                    ).public_key(
                        public_key
                    ).serial_number(
                        x509.random_serial_number()
                    ).not_valid_before(
                        datetime.datetime.now(datetime.timezone.utc)
                    ).not_valid_after(
                        # Chứng chỉ có hiệu lực trong 1 năm
                        datetime.datetime.now(datetime.timezone.utc)+ datetime.timedelta(days = 365)
                    ).add_extension(
                        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                        critical = False,
                    ).sign(private_key, hashes.SHA256())


        # Giả định phân phát cert cho user và phân phối cert và key cho Center Autho
        with open("./TA/server.key", "wb") as key_file:
            key_file.write(private_key.private_bytes(
                encoding = Encoding.PEM,
                format = PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm = NoEncryption()
        ))

            
        with open("./TA/server.crt", "wb") as cert_file:
            cert_file.write(cert.public_bytes(Encoding.PEM))
        
        with open("server.crt", "wb") as cert_file:
            cert_file.write(cert.public_bytes(Encoding.PEM))


def main():
    CA = signature()
    CA.Self_signed_certificate()
    
if __name__ == '__main__':
    main()