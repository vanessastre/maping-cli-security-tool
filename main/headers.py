import requests
import json

def load_json(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

def get_headers(url):
    """
    Retrieves the headers from a given URL.

    Args:
        url (str): The URL for which to retrieve headers.

    Returns:
        dict or None: A dictionary containing the response headers if the request is successful, None if it fails.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()  # Ensure we catch HTTP errors
        return response.headers
    except requests.exceptions.RequestException as e:
        print(f"Error obtaining headers: {e}")
        return None

def print_header_analysis(status, message, recommendation=None, links=None):
    """
    Prints the analysis of a header with a status, message, recommendation, and additional information.

    Args:
        status (str): The status symbol to display (e.g., '✅' or '❌').
        message (str): The message to display.
        recommendation (str, optional): Recommendation text to display if available.
        links (list of str, optional): List of URLs for additional reading.
    """
    print(f"{status} {message}\n")
    if recommendation:
        print(f"\tRecommendation: {recommendation}")
    if links:
        for link in links:
            print(f"\tYou can read more about this here: \033[94m{link}\033[0m")
    print()

def analyze_x_content_type_options(headers, messages):
    """
    Analyzes the X-Content-Type-Options header.

    Args:
        headers (dict): A dictionary containing the HTTP response headers.
        messages (dict): A dictionary containing the messages from the JSON file.
    """
    if 'X-Content-Type-Options' in headers:
        print_header_analysis(
            status='✅',
            message=messages['x_content_type_options']['present'],
        )
    else:
        print_header_analysis(
            status='❌',
            message=messages['x_content_type_options']['not_present'],
            recommendation=messages['x_content_type_options']['not_present_recommendation'],
            links=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-content-type-options"]
        )

def analyze_x_frame_options(headers, messages):
    """
    Analyzes the X-Frame-Options header.

    Args:
        headers (dict): A dictionary containing the HTTP response headers.
        messages (dict): A dictionary containing the messages from the JSON file.
    """
    if 'X-Frame-Options' in headers:
        x_frame_option_value = headers['X-Frame-Options'].strip().lower()
        if x_frame_option_value == 'deny':
            print_header_analysis(
                status='✅',
                message=messages['x_frame_options']['present_deny']
            )
        else:
            print_header_analysis(
                status='⚠️',
                message=messages['x_frame_options']['present_other'].format(value=x_frame_option_value),
                recommendation=messages['x_frame_options']['present_other_recommendation'],
                links=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options"]
            )
    else:
        print_header_analysis(
            status='❌',
            message=messages['x_frame_options']['not_present'],
            recommendation=messages['x_frame_options']['not_present_recommendation'],
            links=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options"]
        )

def analyze_content_security_policy(headers, messages):
    """
    Analyzes the Content-Security-Policy header.

    Args:
        headers (dict): A dictionary containing the HTTP response headers.
        messages (dict): A dictionary containing the messages from the JSON file.
    """
    csp_header_exists = any(header.lower().startswith('content-security-policy') for header in headers)
    if csp_header_exists:
        print_header_analysis(
            status='✅',
            message=messages['content_security_policy']['present']
        )
    else:
        print_header_analysis(
            status='❌',
            message=messages['content_security_policy']['not_present'],
            recommendation=messages['content_security_policy']['not_present_recommendation'],
            links=["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html#1-content-security-policy-header"]
        )

def analyze_fingerprinting(headers, messages):
    """
    Analyzes fingerprinting headers.

    Args:
        headers (dict): A dictionary containing the HTTP response headers.
        messages (dict): A dictionary containing the messages from the JSON file.
    """
    fingerprinting_headers = ['X-Powered-By', 'Server', 'X-AspNet-Version']
    found_headers = [header for header in fingerprinting_headers if header in headers]
    
    if not found_headers:
        print_header_analysis(
            status='✅',
            message=messages['fingerprinting_headers']['not_found']
        )
    else:
        print_header_analysis(
            status='❌',
            message=messages['fingerprinting_headers']['found'].format(headers=', '.join(found_headers)),
            recommendation=messages['fingerprinting_headers']['found_recommendation'],
            links=[
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-powered-by",
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server",
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-aspnet-version"
            ]
        )

def analyze_content_type(headers, messages):
    """
    Analyzes the Content-Type header.

    Args:
        headers (dict): A dictionary containing the HTTP response headers.
        messages (dict): A dictionary containing the messages from the JSON file.
    """
    if 'Content-Type' in headers:
        content_type = headers['Content-Type'].strip().lower()
        if 'text/html' in content_type:
            print_header_analysis(
                status='✅',
                message=messages['content_type']['correct'].format(content_type=content_type)
            )
        else:
            print_header_analysis(
                status='❌',
                message=messages['content_type']['incorrect'].format(content_type=content_type),
                recommendation=messages['content_type']['incorrect_recommendation'],
                links=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#content-type"]
            )
    else:
        print_header_analysis(
            status='❌',
            message=messages['content_type']['not_found'],
            recommendation=messages['content_type']['not_found_recommendation'],
            links=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#content-type"]
        )

def analyze_headers(url, language):
    """
    Analyzes all headers of a given URL.

    Args:
        url (str): The URL for which to analyze headers.
        language (str): The language to use for the messages ('en' or 'es').
    """
    if language == 'es':
        messages = load_json('main/es.json')
    else:
        messages = load_json('main/en.json')

    headers = get_headers(url)
    if headers:
        print("\n\033[1m-------------------------------------------------------------------------------------------\033[0m")
        print("\n\033[1m                        {}\033[0m".format(messages['header_analysis']))
        print("\033[1m-------------------------------------------------------------------------------------------\033[0m\n")
        
        analyze_x_content_type_options(headers, messages)
        analyze_x_frame_options(headers, messages)
        analyze_content_security_policy(headers, messages)
        analyze_fingerprinting(headers, messages)
        analyze_content_type(headers, messages)
    else:
        print("Could not retrieve headers from the provided URL.")
