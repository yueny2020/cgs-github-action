def hardcoded_ip_address_noncompliant():
    sock = socket(AF_INET, SOCK_STREAM)
    # Noncompliant: IP address is hardcoded.
    sock.bind(('193.168.14.31', 80))
