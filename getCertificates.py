import dataclasses
from urllib.parse import urlparse
from os.path import exists
from socket import AF_INET, SOCK_DGRAM
from datetime import datetime
import OpenSSL.crypto
import argparse
import ssl
import socket
import ipaddress
import csv
import logging

logging.basicConfig(filename='DEBUG.log', level=logging.DEBUG)

@dataclasses.dataclass
class CertificateData:
    hostname: str
    ip_address: str
    port: int
    common_name: str
    expiration_date: str
    serial_number: str
    thumbprint: str
    san: str

certificate_data = []

def get_certificate_san(x509cert):
    san = ''
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__()
    return san

def get_certificate_common_name(cert):
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
    subject = x509.get_subject()
    common_name = None
    
    for name, value in subject.get_components():
        if name == b'CN':
            common_name = value.decode('utf-8')
            break
    return common_name

def get_ip_address(address, port=443):
    try:
        ip_list = []
        hostname_ip = socket.getaddrinfo(address, port, proto=socket.IPPROTO_TCP)

        if len(hostname_ip) == 1:
            ip_list.append(hostname_ip[0][4][0])
        else:
            for i in range(len(hostname_ip)):
                ip_address = hostname_ip[i][4][0]
                ip_list.append(ip_address)
            ip_list = ', '.join(str(x) for x in ip_list)

        logging.debug(f'IP list: {ip_list}')
        return ip_list
    except socket.gaierror as e:
        logging.error(f'DNS resolution failed for {address}:{port}: {e}')
        return 'NA'

def get_certificate_from_binary(cert_binary, address, port=443):
    global certificate_data

    try:
        if cert_binary:
            ans1_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_binary)

            serial = ans1_cert.get_serial_number()
            fingerprint = ans1_cert.digest("sha1")
            cert_san = get_certificate_san(ans1_cert) or "N/A"
            cert_common_name = get_certificate_common_name(cert_binary)
            
            exp_date = get_formatted_date(ans1_cert.get_notAfter().decode('utf-8'))
            serial_number = f'{serial:x}'
            thumbprint = fingerprint.decode('utf-8').replace(':', '')
            ip_a = get_ip_address(address, port)

    except (socket.gaierror, ssl.SSLError, ConnectionRefusedError) as e:
        print(f'ssl handshake failed for {address}, {port}')
        logging.debug(f'ssl handshake failed for {address}, {port}')
        logging.error(e)
        certificate_data.append([address, 'NA', 'NA', 'NA', 'NA', 'NA', 'NA'])
        return

    print(f'SSL Certificate for {address}\n'
          f'IP address = {ip_a}\n'
          f'Port = {port}\n'
          f'Common Name = {cert_common_name}\n'
          f'Expires on = {exp_date}\n'
          f'serial# = {serial_number}\n'
          f'Thumbprint = {thumbprint}\n'
          f'SAN = {cert_san}\n')
    certificate_data.append([address, ip_a, port, cert_common_name, exp_date, serial_number, thumbprint, cert_san])

def get_formatted_date(timestamp):
    input_string = datetime.strptime(timestamp, '%Y%m%d%H%M%SZ')
    exp_date_string = input_string.strftime('%A, %B, %d, %Y, %I:%M:%S %p')
    print(exp_date_string)
    return exp_date_string

def write_to_csv(output):
    header = ['Hostname', 'IP Address', 'Port', 'Common Name', 'Expiration Date', 'Serial Number', 'Thumbprint (SHA1)', 'SAN']

    with open(output, 'w', encoding='UTF8', newline='\n') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for i, value in enumerate(certificate_data):
            writer.writerow(value)
        f.close()

def is_ipv4(string):
    try:
        ipaddress.IPv4Network(string)
        logging.debug(f'Domain string is an IP address: {string}')
        return True
    except ValueError:
        logging.debug(f'Domain string is NOT an IP address: {string}')
        return False

def is_ssl_certificate_present(address, port=443):
    try:
        context = ssl.create_default_context()
        
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        
        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=address) as ssock:
            ssock.settimeout(5)
            ssock.verify_mode = False
            ssock.connect((address, port))
            
            cert = ssock.getpeercert(binary_form=True)
            
            if cert:
                logging.info(f'Certificate exists for {address}:{port}')
                return cert
            else:
                logging.info(f'No certificate found for {address}:{port}')
        return None
        
    except (ConnectionResetError, ConnectionRefusedError, socket.gaierror) as e:
        print(f'{address}:{port} is not reachable')
        logging.warning(f'{address}:{port} is not reachable')
        logging.error(f'error while checking certificate: {e}')
        return None
    except socket.timeout:
        logging.error(f'socket timed out while checking certificate for {address}:{port}')
        return None

def clean_input_domains(line):
    domain = urlparse(line).path
    
    if line == '':
        print(line, " is not valid, don't have an empty line")
        logging.error(f'{line} is empty')
    elif '://' in line:
        print(line, " is not valid, please remove http:// and such")
        logging.error(f'URLparse does not like the domain {line} and should be removed')
    elif ':' in line:
        if line.count(':') > 1:
            print(f"bad domains too many colons in line {line} \n")
            logging.error(f"bad domains too many colons in line {line} \n")
            certificate_data.append([line, 'NA', 'NA', 'NA', 'NA', 'NA', 'NA'])
            return False
        else:
            print(domain)
            logging.debug(f'The Domain {line} has a port')
            port_loc = line.find(':')
            port = line[port_loc+1:]
            domain = line[:port_loc]
            cert_info = is_ssl_certificate_present(domain, int(port))
            
            if cert_info:
                get_certificate_from_binary(cert_info, domain, int(port))
            else:
                print(line, "is down")
                logging.error(f'{line} is down')
                certificate_data.append([line, 'NA', 'NA', 'NA', 'NA', 'NA', 'NA'])
    else:
        print(domain)
        cert_info = is_ssl_certificate_present(domain)
        
        if cert_info:
            get_certificate_from_binary(cert_info, domain)
        else:
            print("site is down")
            logging.error(f'{domain} is down')
            certificate_data.append([line, 'NA', 'NA', 'NA', 'NA', 'NA', 'NA'])

def argsetup():
    about = 'Query a domain for its certificate and get serial, Thumbprint, SANS, expiration'
    parser = argparse.ArgumentParser(description=about)
    parser.add_argument('-f', '--domainFile', type=str, help='This is the file with list of domains, one domain per line')
    parser.add_argument('-s', '--single', type=str, help='This is to query a single domain with its info')
    parser.add_argument('-o', '--output', type=str, help='filename to save as')
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = argsetup()
    file = args.domainFile
    domain = args.single
    output = args.output
    
    if file:
        logging.debug(f"reading from file with list of domains: {file}")
        with open(file) as rb:
            lines = rb.readlines()
            for line in lines:
                clean_input_domains(line.strip())
    
    elif domain:
        logging.debug(f"Checking single domain: {domain}")
        clean_input_domains(domain)
    
    else:
        logging.debug("Argument needed, either -f or -s ")
        print("include either -f for file of domains to check or -s for single domain")

    if output:
        file_exists = exists(output)
        if file_exists:
            logging.info(f"A file with the same name already exists: {output}")
            print("file already exists")
            replace_file = input("would you like to replace? Y/N: ").upper()
            if replace_file == 'Y':
                logging.info(f"User Selected to overwrite: {output}")
                write_to_csv(output)
            elif replace_file == 'N':
                logging.info(f"User Selected to NOT to overwrite, need a new filename")
                output = input("Enter a new file name: ")
                write_to_csv(output)
            else:
                exit()
        else:
            write_to_csv(output)

    print(certificate_data)