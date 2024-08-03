import requests

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

def analyze_x_content_type_options(headers):
    """
    Analyzes the X-Content-Type-Options header.

    Args:
        headers (dict): A dictionary containing the HTTP response headers.
    """
    if 'X-Content-Type-Options' in headers:
        print_header_analysis(
            status='✅',
            message='The X-Content-Type-Options header is sent: nosniff',
        )
    else:
        print_header_analysis(
            status='❌',
            message='The X-Content-Type-Options header is not present',
            recommendation="Properly configure the Content-Type header across the site.",
            links=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-content-type-options"]
        )

def analyze_x_frame_options(headers):
    """
    Analyzes the X-Frame-Options header.

    Args:
        headers (dict): A dictionary containing the HTTP response headers.
    """
    if 'X-Frame-Options' in headers:
        x_frame_option_value = headers['X-Frame-Options'].strip().lower()
        if x_frame_option_value == 'deny':
            print_header_analysis(
                status='✅',
                message='The X-Frame-Options header is set to: deny'
            )
        else:
            print_header_analysis(
                status='⚠️',
                message=f'The X-Frame-Options header is present, but its value is: {x_frame_option_value}',
                recommendation="Change the X-Frame-Options header value to 'deny' for better security.",
                links=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options"]
            )
    else:
        print_header_analysis(
            status='❌',
            message='The X-Frame-Options header is not present: deny',
            recommendation="Prevent the page from being displayed in a frame. If possible, use the CSP frame-ancestors directive instead of X-Frame-Options.",
            links=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-frame-options"]
        )

def analyze_content_security_policy(headers):
    """
    Analyzes the Content-Security-Policy header.

    Args:
        headers (dict): A dictionary containing the HTTP response headers.
    """
    csp_header_exists = any(header.lower().startswith('content-security-policy') for header in headers)
    if csp_header_exists:
        print_header_analysis(
            status='✅',
            message='The Content-Security-Policy header is sent.'
        )
    else:
        print_header_analysis(
            status='❌',
            message='Content-Security-Policy header not found.',
            recommendation="Configuring and maintaining a Content Security Policy (CSP) is crucial to detect and mitigate certain types of attacks.",
            links=["https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html#1-content-security-policy-header"]
        )

def analyze_fingerprinting(headers):
    """
    Analyzes fingerprinting headers.

    Args:
        headers (dict): A dictionary containing the HTTP response headers.
    """
    fingerprinting_headers = ['X-Powered-By', 'Server', 'X-AspNet-Version']
    found_headers = [header for header in fingerprinting_headers if header in headers]
    
    if not found_headers:
        print_header_analysis(
            status='✅',
            message='No server fingerprinting headers found - X-Powered-By, Server, X-AspNet-Version.'
        )
    else:
        print_header_analysis(
            status='❌',
            message=f'Found headers {", ".join(found_headers)}',
            recommendation="Remove or set non-informative values for these headers.",
            links=[
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-powered-by",
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server",
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#x-aspnet-version"
            ]
        )

def analyze_content_type(headers):
    """
    Analyzes the Content-Type header.

    Args:
        headers (dict): A dictionary containing the HTTP response headers.
    """
    if 'Content-Type' in headers:
        content_type = headers['Content-Type'].strip().lower()
        if 'text/html' in content_type:
            print_header_analysis(
                status='✅',
                message=f'Correct content type for the response: {content_type}'
            )
        else:
            print_header_analysis(
                status='❌',
                message=f'The Content-Type header is present, but its value is: {content_type}',
                recommendation="Properly set the Content-Type header to 'text/html' if the content is HTML. The charset attribute is necessary to prevent XSS on HTML pages.",
                links=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#content-type"]
            )
    else:
        print_header_analysis(
            status='❌',
            message='Content-Type header not found',
            recommendation="Ensure that the Content-Type header is properly set in the response to avoid issues in content interpretation by the client.",
            links=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#content-type"]
        )

def analyze_headers(url):
    """
    Analyzes all headers of a given URL.

    Args:
        url (str): The URL for which to analyze headers.
    """
    headers = get_headers(url)
    if headers:
        print("\n\033[1m-------------------------------------------------------------------------------------------\033[0m")
        print("\033[1m\n                    HEADERS ANALYSIS:\033[0m \n")
        print("\033[1m-------------------------------------------------------------------------------------------\033[0m\n")
        
        analyze_x_content_type_options(headers)
        analyze_x_frame_options(headers)
        analyze_content_security_policy(headers)
        analyze_fingerprinting(headers)
        analyze_content_type(headers)
    else:
        print("Could not retrieve headers from the provided URL.")
