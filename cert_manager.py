import os
import socket
import datetime
from typing import Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import ipaddress

CERT_FILE = os.path.join(os.path.dirname(__file__), "cert.pem")
KEY_FILE = os.path.join(os.path.dirname(__file__), "key.pem")

def get_local_ip() -> str:
    """Detects the primary local LAN IP address (e.g. 192.168.x.x)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't actually send packets or make external connections
        s.connect(("10.255.255.255", 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip

def generate_self_signed_cert(cert_path: str = CERT_FILE, key_path: str = KEY_FILE) -> Tuple[str, str, str]:
    """
    Generates a secure self-signed SSL/TLS certificate for local Wi-Fi encryption
    with SANs matching localhost, 127.0.0.1, and the current local LAN IP.
    """
    local_ip = get_local_ip()

    # If certificates already exist, just return them
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path, local_ip

    # Generate RSA private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Subject & Issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Local Relay (ETIPOS)"),
        x509.NameAttribute(NameOID.COMMON_NAME, local_ip),
    ])

    # Build SANs (Subject Alternative Names)
    san_entries = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    try:
        san_entries.append(x509.IPAddress(ipaddress.IPv4Address(local_ip)))
    except Exception:
        pass

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Write private key
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert_path, key_path, local_ip

if __name__ == "__main__":
    c_path, k_path, ip = generate_self_signed_cert()
    print(f"Generated SSL Certificate at: {c_path}")
    print(f"Generated SSL Private Key at: {k_path}")
    print(f"Detected Local IP: {ip}")

