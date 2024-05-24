import socket

def lookup_dns(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

def reverse_dns(ip):
    try:
        hostnames = socket.gethostbyaddr(ip)
        return hostnames[0], hostnames[1]
    except socket.herror:
        return None, []
