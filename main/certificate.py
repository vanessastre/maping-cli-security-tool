import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def get_certificate(url):
    """
    Obtains the SSL certificate from a given URL.

    Args:
        url (str): The URL from which to obtain the SSL certificate.

    Returns:
        dict or None: A dictionary containing the details of the SSL certificate, or None if the request fails.
    """
    hostname = url.split("//")[-1].split("/")[0]
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.getpeercert()
    except (socket.gaierror, socket.error) as e:
        print(f"Connection error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    
    return None

def get_certificate_pem(url):
    """
    Obtains the SSL certificate in PEM format from a given URL.

    Args:
        url (str): The URL from which to obtain the SSL certificate.

    Returns:
        bytes: The SSL certificate in PEM format.
    """
    hostname = url.split("//")[-1].split("/")[0]
    context = ssl.create_default_context()
    
    with socket.create_connection((hostname, 443)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert_der = ssock.getpeercert(True)
            return ssl.DER_cert_to_PEM_cert(cert_der).encode('utf-8')

def get_common_name(cert):
    """
    Obtains the common name (commonName) from the SSL certificate.

    Args:
        cert (dict): A dictionary containing the details of the SSL certificate.

    Returns:
        str: The common name (commonName) of the SSL certificate.
    """
    common_name = ""
    subject = cert.get("subject", [])
    
    for item in subject:
        if isinstance(item, tuple) and item[0] == "commonName":
            common_name = item[1]
            break

    return common_name

def get_key_size(url):
    """
    Obtains and returns the key size of the SSL certificate from a given URL.

    Args:
        url (str): The URL from which to obtain the SSL certificate.

    Returns:
        int: The key size of the SSL certificate.
    """
    cert_pem = get_certificate_pem(url)
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    return cert.public_key().key_size

def analyze_key_strength(url):
    """
    Analyzes the strength of the SSL certificate's key.

    Args:
        url (str): The URL for which to analyze the SSL certificate.
    """
    key_size = get_key_size(url)
    if key_size >= 2048:
        print(f"✅ Key strength sufficient: {key_size} bits\n")
    else:
        print(f"❌ Key strength insufficient: {key_size} bits")
        print("\tRecommendation: Use a private key of at least 2048 bits.")
        print("\tMore information: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html#use-strong-keys-and-protect-them\033[0m\n")

def analyze_hash_algorithm(url):
    """
    Analyzes the hash algorithm used in the SSL certificate.

    Args:
        url (str): The URL for which to analyze the SSL certificate.
    """
    cert_pem = get_certificate_pem(url)
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    signature_algorithm = cert.signature_algorithm_oid._name

    if "sha256" in signature_algorithm.lower():
        print("✅ Cryptographic hash algorithm: SHA-256\n")
    else:
        print(f"❌ Cryptographic hash algorithm is not SHA-256: {signature_algorithm}")
        print("\tRecommendation: Use SHA-256 for hashing instead of older algorithms.")
        print("\tMore information: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html#use-strong-cryptographic-hashing-algorithms\033[0m\n")

def analyze_domain_names(url, cert):
    """
    Analyzes the domain names in the SSL certificate.

    Args:
        url (str): The URL for which the SSL certificate was obtained.
        cert (dict): A dictionary containing the details of the SSL certificate.
    """
    hostname = url.split("//")[-1].split("/")[0]
    san_list = [entry[1] for entry in cert.get('subjectAltName', []) if entry[0].lower() == 'dns']
    common_name = get_common_name(cert)
    
    if hostname == common_name or hostname in san_list:
        print("✅ Domain names match the certificate\n")
    else:
        print("❌ Domain names do not match the certificate")
        print("\tRecommendation: Ensure the domain name matches the fully qualified domain name of the server.")
        print("\tMore information: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html#use-correct-domain-names\033[0m\n")

def analyze_wildcard_certificate(cert):
    """
    Analyzes whether the SSL certificate is a wildcard certificate.

    Args:
        cert (dict): A dictionary containing the details of the SSL certificate.
    """
    common_name = get_common_name(cert)
    if common_name.startswith("*."):
        print("❌ Wildcard certificate: Avoid using wildcard certificates")
        print("\tRecommendation: Use wildcard certificates only when necessary.")
        print("\tMore information: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html#carefully-consider-the-use-of-wildcard-certificates\033[0m\n")
    else:
        print("✅ Wildcard certificate: Not a wildcard certificate\n")

def analyze_certificate_authority(cert):
    """
    Analyzes the certificate authority of the SSL certificate.

    Args:
        cert (dict): A dictionary containing the details of the SSL certificate.
    """
    issuer_org = next((item[1] for item in cert.get("issuer", []) for item in item if item[0] == 'organizationName'), "")
    
    if "Let's Encrypt" in issuer_org:
        print("✅ Certificate Authority (CA): Issued by Let's Encrypt\n")
    else:
        print("❌ Certificate Authority (CA): Not issued by Let's Encrypt")
        print("\tRecommendation: Use a trusted CA like Let's Encrypt for automatic trust.")
        print("\tMore information: \033[94mhttps://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html#use-an-appropriate-certification-authority-for-the-applications-user-base\033[0m\n")

def analyze_certificate(url):
    """
    Analyzes the SSL certificate of a given URL.

    Args:
        url (str): The URL for which to analyze the SSL certificate.
    """
    cert = get_certificate(url)
    
    if cert:
        print("\n\033[1m-------------------------------------------------------------------------------------------\033[0m")
        print("\033[1m\n                    CERTIFICATE ANALYSIS:\033[0m \n")
        print("\033[1m-------------------------------------------------------------------------------------------\033[0m\n")
        
        analyze_key_strength(url)
        analyze_hash_algorithm(url)
        analyze_domain_names(url, cert)
        analyze_wildcard_certificate(cert)
        analyze_certificate_authority(cert)
    else:
        print("Could not obtain the SSL certificate from the provided URL.")
