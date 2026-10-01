import socket
import ssl
import re
from sys import stdin

def parse_uri(uri):

    pattern = r"^([a-zA-Z0-9._%-]*)(?::\/\/)?([a-zA-Z._&-]+)(?::?)(\d*)(/?[a-zA-Z0-9._&-/]*)"

    match = re.match(pattern, uri)
    if match:
        protocol, host, port, filepath = match.groups()

        if (port != "") and ((protocol == "https" and port != "443") or (protocol == "http" and port != "80")):
            raise ValueError(f"Protocol {protocol} does not take in port {port}. Please enter valid uri.")
        return protocol, host, port, filepath

def parse_response(response):
    head, _, body = response.partition('\r\n\r\n')
    responseCode = int(head.split(' ')[1]) if head else None
    return head, body, responseCode

def extract_cookies(headers):
    cookies = {}

    parsedHeaders = headers.split("\r\n")

    pattern = r"Set-Cookie:\s*([^=]+)=([^;]+)(?:.*?\bexpires=([^;]+))?(?:.*?\bdomain=([^;]+))?"
    for headLine in parsedHeaders:
        match = re.match(pattern, headLine, flags=re.DOTALL)
        if match:
            cookieName, cookieValue, expires, domain = match.groups()
            cookies[cookieName] = (cookieValue, expires, domain)
    return cookies

class WebTester:
    def __init__(self, protocol, host, port, filepath):
         
        self.protocol = protocol
        self.host = host
        self.port = port if port == "" else int(port)
        self.filepath = filepath
        self.cookies = {}
        self.head, self.body, self.statusCode = "", "", 0

        try:
            self.context = ssl.create_default_context()
            self.context.set_alpn_protocols(['http/1.1'])
        except ssl.SSLError:
            print("fail")
            

    def open_connection(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        is_https = self.protocol == "https" or self.port == 443

        target_port = self.port if self.port != "" else (443 if is_https else 80)
        self.socket.connect((self.host, target_port))

        if is_https:
            self.socket = self.context.wrap_socket(self.socket, server_hostname=self.host)

    def send_http_request(self):
        self.filepath = self.filepath if self.filepath else "/"
        self.request = f"GET {self.filepath} HTTP/1.1\r\nHost: {self.host}\r\nConnection: close\r\n\r\n".encode('utf-8')
        self.socket.sendall(self.request)

    def receive_response(self):
        reply = b""
        while True:
            data = self.socket.recv(4096)
            if not data:
                break
            reply += data
        reply = reply.decode('utf-8', errors="replace")

        self.head, self.body, self.statusCode = parse_response(reply)


    def handle_redirects(self):
        if self.statusCode == 301 or 302:
            while self.statusCode in (301, 302):
                location = ""
                for line in self.head.split("\r\n"):
                    if line.lower().startswith("location:"):
                        location = line.split(":", 1)[1].strip()
                        break

                # new instance of connection

                # set up uri for parsing 
                if location.startswith('/'):
                    self.filepath = location
                else:
                    newUri = location
                    if "https" not in newUri and "http" not in newUri:
                        newUri = "https://" + newUri

                    # reconfigure webTester attributes
                    self.filepath = self.filepath if self.filepath else "/"
                    self.protocol, self.host, self.port, self.filepath = parse_uri(newUri)
                self.request = f"GET {self.filepath} HTTP/1.1\r\nHost: {self.host}\r\nConnection: close\r\n\r\n".encode('utf-8')

                # open a new connection, send request and recieve response
                self.open_connection()
                self.send_http_request()
                self.receive_response()
        if self.statusCode == 200:
            pass
        elif self.statusCode == 505:
            print("HTTP Verison not Supported")

    def check_http2_support(self):
        supporthttp2 = "no"
        if self.protocol != "https" and self.port != 443:
            return supporthttp2
            
        context = ssl.create_default_context()
        context.set_alpn_protocols(['http/1.1', 'h2'])
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, 443))
        conn = context.wrap_socket(sock, server_hostname=self.host)
        proto = conn.selected_alpn_protocol()
        if proto == 'h2':
            supporthttp2 = "yes"
        else:
            supporthttp2 = "no"
            
        conn.close()
        return supporthttp2

    def check_password_protection (self):
        passwordProtected = "yes" if self.statusCode == 401 else "no"
        return passwordProtected


def main():

    uri = input("Enter URI: ")
    if "https" not in uri and "http" not in uri:
        uri = "https://" + uri
    try:
        webTester = WebTester(*parse_uri(uri))
        webTester.open_connection()
        webTester.send_http_request()
        webTester.receive_response()
        webTester.handle_redirects()
        http2Support = webTester.check_http2_support()
        webTester.socket.close()
        cookies = extract_cookies(webTester.head)
        passwordProtected = webTester.check_password_protection()

        print("website: "+webTester.host)
        print("1. Supports http2: " + http2Support)
        print("2. List of Cookies:")
        for cookie in cookies.keys():
            print("cookie name: " +cookie, end = "")
            if cookies[cookie][1]:
                print(", expires time: " + cookies[cookie][1], end = "")
            if cookies[cookie][2]:
                print(", domain name: " + cookies[cookie][2], end = "")
            print("")
        print("3. password-protected: " + passwordProtected)

    except ValueError as error:
        print(f"[Error] {error}")
    except socket.gaierror as error:
        print(f"{error}. Address could not be found. please enter a valid uri.")

    return
            

if __name__ == "__main__":
    main()