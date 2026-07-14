"""Command-line interface and argument parsing."""

import getopt
import sys

from .banner import print_help
from .scanner import SSRFScanner


async def main():
    try:
        opts, args = getopt.getopt(
            sys.argv[1:], 
            "hu:f:b:dc:qH:",   # added H:
            ["help", "url=", "file=", "backurl=", "debug", "cookie=", 
             "concurrency=", "rate-limit=", "limit-per-host=", "quiet", "proxy=", 
             "proxy-auth=", "output-format=", "header=",
             # Out-of-band (OOB) confirmation options
             "oob-mode=", "oob-listen=", "oob-domain=", "oob-wait="]
        )

    except getopt.GetoptError as err:
        print(str(err))
        sys.exit(2)

    url = None
    url_file = None
    backurl = None
    debug = False
    cookies = None
    concurrency = 200
    rate_limit = 100
    limit_per_host = 0  # 0 = auto (align with concurrency)
    quiet = False
    proxy = None
    proxy_auth = None
    output_format = 'csv'
    custom_headers = []  # list of raw "-H 'Name: value'" strings
    oob_mode = 'off'
    oob_listen = '0.0.0.0:8000'
    oob_domain = ''
    oob_wait = 8


    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print_help()
            sys.exit()
        elif opt in ("-u", "--url"):
            url = arg
        elif opt in ("-f", "--file"):
            url_file = arg
        elif opt in ("-b", "--backurl"):
            backurl = arg
        elif opt in ("-d", "--debug"):
            debug = True
        elif opt in ("-c", "--cookie"):
            cookies = arg
        elif opt == "--concurrency":
            concurrency = int(arg)
        elif opt == "--rate-limit":
            rate_limit = int(arg)
        elif opt == "--limit-per-host":
            try:
                limit_per_host = int(arg)
            except ValueError:
                limit_per_host = 0
        elif opt in ("-q", "--quiet"):
            quiet = True
        elif opt == "--proxy":
            proxy = arg
        elif opt == "--proxy-auth":
            proxy_auth = arg
        elif opt == "--output-format":
            output_format = arg
        elif opt in ("-H", "--header"):
            # e.g. -H "Authorization: Bearer xyz"
            custom_headers.append(arg)
        elif opt == "--oob-mode":
            oob_mode = arg
        elif opt == "--oob-listen":
            oob_listen = arg
        elif opt == "--oob-domain":
            oob_domain = arg
        elif opt == "--oob-wait":
            try:
                oob_wait = int(arg)
            except ValueError:
                oob_wait = 8


    if not (url or url_file):
        print("Error: Must provide either URL or file")
        sys.exit(1)

    scanner = SSRFScanner()
    if debug:
        scanner.config.scanner['debug'] = True
    if backurl:
        scanner.backurl = backurl
    if cookies:
        scanner.cookies = cookies

    # Apply static headers from CLI (-H/--header) to all requests
    if custom_headers:
        # Ensure the attribute exists
        if not hasattr(scanner, "static_headers"):
            scanner.static_headers = {}
        for hdr in custom_headers:
            # Expect "Name: value"
            name, sep, value = hdr.partition(':')
            if not sep:
                # Skip invalid header without ':'
                continue
            scanner.static_headers[name.strip()] = value.strip()
    
    # Apply CLI overrides
    scanner.config.scanner['concurrency'] = concurrency
    scanner.config.scanner['limit_per_host'] = limit_per_host
    scanner.config.rate_limiting['requests_per_second'] = rate_limit
    scanner.config.scanner['proxy'] = proxy
    scanner.config.scanner['proxy_auth'] = proxy_auth
    scanner.config.output['format'] = output_format
    scanner.quiet_mode = quiet

    # Out-of-band confirmation settings
    scanner.oob_mode = oob_mode
    scanner.oob_listen = oob_listen
    scanner.oob_domain = oob_domain
    scanner.oob_wait = oob_wait

    await scanner.run(urls=[url] if url else None, url_file=url_file)

