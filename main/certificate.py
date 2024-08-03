import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import json

def load_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

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

def analyze_key_strength(url, messages):
    """
    Analyzes the strength of the SSL certificate's key.

    Args:
        url (str): The URL for which to analyze the SSL certificate.
        messages (dict): A dictionary containing the messages from the JSON file.
    """
    key_size = get_key_size(url)
    if key_size >= 2048:
        print(f"✅ {messages['key_strength']['sufficient'].format(key_size)}\n")
    else:
        print(f"❌ {messages['key_strength']['insufficient'].format(key_size)}")
        print(f"\tRecommendation: {messages['key_strength']['recommendation']}")
        print(f"\tMore information: \033[94m{messages['key_strength']['more_info']}\033[0m\n")

def analyze_hash_algorithm(url, messages):
    """
    Analyzes the hash algorithm used in the SSL certificate.

    Args:
        url (str): The URL for which to analyze the SSL certificate.
        messages (dict): A dictionary containing the messages from the JSON file.
    """
    cert_pem = get_certificate_pem(url)
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    signature_algorithm = cert.signature_algorithm_oid._name

    if "sha256" in signature_algorithm.lower():
        print(f"✅ {messages['hash_algorithm']['sha256']}\n")
    else:
        print(f"❌ {messages['hash_algorithm']['not_sha256'].format(signature_algorithm)}")
        print(f"\tRecommendation: {messages['hash_algorithm']['recommendation']}")
        print(f"\tMore information: \033[94m{messages['hash_algorithm']['more_info']}\033[0m\n")

def analyze_domain_names(url, cert, messages):
    """
    Analyzes the domain names in the SSL certificate.

    Args:
        url (str): The URL for which the SSL certificate was obtained.
        cert (dict): A dictionary containing the details of the SSL certificate.
        messages (dict): A dictionary containing the messages from the JSON file.
    """
    hostname = url.split("//")[-1].split("/")[0]
    san_list = [entry[1] for entry in cert.get('subjectAltName', []) if entry[0].lower() == 'dns']
    common_name = get_common_name(cert)
    
    if hostname == common_name or hostname in san_list:
        print(f"✅ {messages['domain_names']['match']}\n")
    else:
        print(f"❌ {messages['domain_names']['no_match']}")
        print(f"\tRecommendation: {messages['domain_names']['recommendation']}")
        print(f"\tMore information: \033[94m{messages['domain_names']['more_info']}\033[0m\n")

def analyze_wildcard_certificate(cert, messages):
    """
    Analyzes whether the SSL certificate is a wildcard certificate.

    Args:
        cert (dict): A dictionary containing the details of the SSL certificate.
        messages (dict): A dictionary containing the messages from the JSON file.
    """
    common_name = get_common_name(cert)
    if common_name.startswith("*."):
        print(f"❌ {messages['wildcard_certificate']['wildcard']}")
        print(f"\tRecommendation: {messages['wildcard_certificate']['recommendation']}")
        print(f"\tMore information: \033[94m{messages['wildcard_certificate']['more_info']}\033[0m\n")
    else:
        print(f"✅ {messages['wildcard_certificate']['not_wildcard']}\n")

def analyze_certificate_authority(cert, messages):
    """
    Analyzes the certificate authority of the SSL certificate.

    Args:
        cert (dict): A dictionary containing the details of the SSL certificate.
        messages (dict): A dictionary containing the messages from the JSON file.
    """
    issuer_org = next((item[1] for item in cert.get("issuer", []) for item in item if item[0] == 'organizationName'), "")
    
    if "Let's Encrypt" in issuer_org:
        print(f"✅ {messages['certificate_authority']['lets_encrypt']}\n")
    else:
        print(f"❌ {messages['certificate_authority']['not_lets_encrypt']}")
        print(f"\tRecommendation: {messages['certificate_authority']['recommendation']}")
        print(f"\tMore information: \033[94m{messages['certificate_authority']['more_info']}\033[0m\n")

def analyze_certificate(url, language):
    """
    Analyzes the SSL certificate of a given URL.

    Args:
        url (str): The URL for which to analyze the SSL certificate.
        language (str): The language to use for the messages ('en' or 'es').
    """
    messages = load_json(f'main/{language}.json')
    cert = get_certificate(url)
    
    if cert:
        print("\n\033[1m-------------------------------------------------------------------------------------------\033[0m")
        print("\n\033[1m                        {}\033[0m".format(messages['certificate_analysis']))
        print("\033[1m-------------------------------------------------------------------------------------------\033[0m\n")
        
        analyze_key_strength(url, messages)
        analyze_hash_algorithm(url, messages)
        analyze_domain_names(url, cert, messages)
        analyze_wildcard_certificate(cert, messages)
        analyze_certificate_authority(cert, messages)
    else:
        print(messages['no_certificate'])
