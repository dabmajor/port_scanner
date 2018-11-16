# modified a port scanning tool I found on github to work with python 3.6
# i've also broken the program up into more functions so the code is more modular and readable
# planning to add a lot more functionality as I play with socket and other network related modules.

import socket
import sys


def main():
    show_user_info()
    # get host, port and timeout info from the user
    ip, port_range, timeout = get_user_input()
    perform_range_scan(ip, port_range, timeout)


# decorator to create and return new wrapped function
def info_decorator(info_output_function):
    def wrapped_function():
        print("****************************************************")
        info_output_function()
        print("****************************************************")
    return wrapped_function


# shows the current user system information
@ info_decorator  # this will overwrite the function with the new wrapped function
def show_user_info():
    print("USER INFO:")
    print("\tHOSTNAME: {}.".format(socket.gethostname()))
    print("\tINET IP: {}.".format(socket.gethostbyname(socket.gethostname())))


# this function does not do the actual scan, it simply calls the scan function for each port specified
def perform_range_scan(ip, port_range, timeout):
    # If the user only entered one port we will only scan the one port
    # otherwise scan the range
    if len(port_range) == 1:
        scan_port(ip, int(port_range[0]), int(timeout))
    else:
        for port in range(int(port_range[0]), int(port_range[1]) + 1):
            scan_port(ip, int(port), int(timeout))


# creates connection to specified IP address and port. If connection fails, None is returned
def connect_to_ip(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        return sock

    except Exception:
        return None


# performs scan of port by attempting to create a socket connection object, using connect_to_ip
def scan_port(ip, port, timeout):
    # if you do not set a socket default timeout, the default is none
    socket.setdefaulttimeout(timeout)
    # creates a new socket object connection to the IP and port
    sock = connect_to_ip(ip, port)

    if sock:
        print('Able to connect to: {0}:{1}'.format(ip, port))
        # closes the connection of the connection was successful
        sock.close()
    else:
        print('Not able to connect to: {0}:{1}'.format(ip, port))


# gets user input and converts the hostname to an IP if needed.
def get_user_input():
    # Get the IP / domain from the user
    ip_domain = input("Enter the ip or domain: ")
    if ip_domain == '':
        print('You must specify a host!')
        sys.exit(0)

    ip = get_ip_from_domain(ip_domain)

    # Get the port range from the user
    port = input("Enter the port range (Ex 20-80): ")
    if port == '':
        print('You must specify a port range!')
        sys.exit(0)

    port_range = port.split("-")

    # Optional: Get the timeout from the user
    timeout = input("Timeout (Default=5): ")
    if not timeout:
        timeout = 5

    return ip, port_range, timeout


def get_ip_from_domain(ip_domain):
    # Get the IP address if the host name is a domain
    try:
        ip = socket.gethostbyname(ip_domain)
    except Exception:
        print('There was an error resolving the domain')
        sys.exit(1)
    return ip


if __name__ == "__main__":
    main()

exit()
