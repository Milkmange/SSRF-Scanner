"""Console banner and help text."""

from colorama import Fore

from . import __version__


def printBanner():
    print("""

            ░██████╗░██████╗██████╗░███████╗
            ██╔════╝██╔════╝██╔══██╗██╔════╝
            ╚█████╗░╚█████╗░██████╔╝█████╗░░
            ░╚═══██╗░╚═══██╗██╔══██╗██╔══╝░░
            ██████╔╝██████╔╝██║░░██║██║░░░░░
            ╚═════╝░╚═════╝░╚═╝░░╚═╝╚═╝
    """)
    print(__version__ + " by Dancas")
    print(Fore.YELLOW + "[WRN] Use with caution. You are responsible for your actions")
    print(Fore.YELLOW + "[WRN] Developers assume no liability and are not responsible for any misuse or damage.")

def print_help():
    print(Fore.GREEN + "SSRF Scanner Help Menu")
    print(Fore.GREEN + "Usage:")
    print("  -h, --help          : Show this help message")
    print("  -u, --url           : Single URL to scan")
    print("  -f, --file          : File containing URLs to scan")
    print("  -b, --backurl       : Callback URL for remote SSRF detection")
    print("  -d, --debug         : Enable debug mode")
    print("  -c, --cookie        : Manually set cookies (format: 'name1=value1; name2=value2')")
    print("  -H, --header        : Custom header to include in requests (format: 'Name: value')")
    print("  --concurrency N     : Number of concurrent requests (default: 200)")
    print("  --rate-limit N      : Max requests per second (default: 100)")
    print("  --limit-per-host N  : Max simultaneous connections per host")
    print("                        (default: 0 = auto, aligned with --concurrency;")
    print("                        set lower to be gentle on a single target)")
    print("  --url-concurrency N : How many URLs (from -f) to scan at once (default: 5)")
    print("  -q, --quiet         : Only show vulnerabilities (no progress)")
    print("  --proxy URL         : Proxy URL (e.g., http://127.0.0.1:8080)")
    print("  --proxy-auth U:P    : Proxy authentication (username:password)")
    print("  --output-format FMT : Output format: json, csv, html, txt, all (default: csv)")
    print(Fore.GREEN + "\nOut-of-band (OOB) confirmation of blind SSRF:")
    print("  --oob-mode MODE     : off | selfhosted (default: off)")
    print("  --oob-listen H:P    : Interface:port to bind the listener (default: 0.0.0.0:8000)")
    print("  --oob-domain DOMAIN : Public authority with wildcard DNS -> listener")
    print("                        (e.g. oob.example.com; *.oob.example.com -> your IP)")
    print("  --oob-wait N        : Seconds to wait for late callbacks (default: 8)")
    print("\nExample:")
    print("  python3 ssrf_scanner.py -u https://example.com")
    print("  python3 ssrf_scanner.py -f urls.txt --concurrency 200")
    print("  python3 ssrf_scanner.py -u https://example.com --proxy http://127.0.0.1:8080")
    print("  python3 ssrf_scanner.py -u https://example.com --output-format html,json")
    print("  python3 ssrf_scanner.py -u https://example.com -q --rate-limit 10")
    print("  python3 ssrf_scanner.py -u https://example.com \\")
    print("      --oob-mode selfhosted --oob-listen 0.0.0.0:8000 --oob-domain oob.example.com")

