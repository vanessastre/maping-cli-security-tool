import argparse
from main import headers, certificate

def print_banner():
    """Prints the application banner."""
    banner_lines = [
        "\033[37m                    \033[32m_ _       _ _     _ _ _                               \033[0m",
        "\033[37m    _ _   _ _     \033[32m_|_|_|_   _|_|_|_  |_|_|_|    \033[37m_ _       _ _     \033[0m",
        "\033[37m  _|_|_|_|_|_|_  \033[32m|_|   |_| |_|   |_|   |_|    \033[37m_|_|_|_   _|_|_|_   \033[0m",
        "\033[37m |_|   |_|   |_| \033[32m|_|_ _|_| |_|_ _|_|   |_|   \033[37m|_|   |_| |_|   |_|  \033[0m",
        "\033[37m |_|   |_|   |_| \033[32m|_|   |_| |_|        _|_|_  \033[37m|_|   |_| |_|_ _|_|  \033[0m",
        "\033[37m |_|   |_|   |_| \033[32m|_|   |_| |_|       |_|_|_| \033[37m|_|   |_|   |_|_|_|  \033[0m",
        "\033[37m                                                         _ _ |_|                  \033[0m",
        "\033[37m                                                        |_|_|_|                   \033[0m",
        "\n                                        Created by Vanessa Sastre",
        "                                                 Version 1.0 2024 \n"
    ]
    for line in banner_lines:
        print(line)

def parse_arguments():
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(description="mAPIng is a security analysis tool")
    parser.add_argument("-u", "--url", help="Specify the URL to analyze", required=True)
    parser.add_argument("-e", "--headers", action="store_true", help="Displays information about the URL's headers")
    parser.add_argument("-c", "--certificate", action="store_true", help="Displays information about the URL's certificate")
    parser.add_argument("--language", choices=['en', 'es'], default='en', help="Specify the language for the output (default: English)")
    return parser.parse_args()

def main():
    """Main function to handle command line arguments and call appropriate functions."""
    args = parse_arguments()

    if not args.headers and not args.certificate:
        args.headers = True
        args.certificate = True

    if args.headers:
        headers.analyze_headers(args.url, args.language)

    if args.certificate:
        certificate.analyze_certificate(args.url, args.language)

if __name__ == "__main__":
    print_banner()
    main()
