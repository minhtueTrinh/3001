# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re

# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  s = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) #According to Python.org, the address family should be default = AF_INET (using IPv4) while socket type is also default SOCK_STREAM
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  s.bind((proxyHost,proxyPort)) #bind the socket to the the assigned host and port identified previously
  print(f"Proxy server's listening on {proxyHost}:{proxyPort}") # print for debugging
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  # since this is a proxy for a HTTP, which uses TCP connection. Hence must use listen() to accept incomong connections
  s.listen(3) # allows maximum 3 queued
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  # Accept connection from client and store in the clientSocket
  try:
    clientSocket, clientAddress = s.accept() #accept() used by server to accept or complete a connection. The accept() method will bloack execution until there is an incoming connection
    print(f"Connected to {clientAddress}") # debugging
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  if not message_bytes:
    print("Cannot receive msg from client")
    clientSocket.close()
    continue # skip to the next connection
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  print ('Requested Resource:\t' + resource)

  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default'

    print ('Cache location:\t\t' + cacheLocation)

    fileExists = os.path.isfile(cacheLocation)
    
    # Check wether the file is currently in the cache
    cacheFile = open(cacheLocation, "r")
    cacheData = cacheFile.readlines() #alternative approach: cacheData = cacheFile.read() --> preserves exact HTTP response including headrs

    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    # ProxyServer finds a cache hit
    # Send back response to client 
    for line in cacheData:
      clientSocket.send(line) #can be sendall(cacheData) send all at once to inprove performance
    cacheFile.close()
    print ('Sent to the client:')
    print ('> ' + cacheData)
  except:
    # cache miss.  Get resource from origin server
    originServerSocket = None #Establish a new variabl to store original server socket 
    # Create a socket to connect to origin server
    # and store in originServerSocket
    originServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) #similar the previous socket: AF_INET = IPv4 and SOCK_STREAM for TCP connections
    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server on defalut HTTP port which is port 80
      originServerSocket.connect((address,80)) #use 'address' variable to avoid double lookup
      print ('Connected to origin Server')
      #add more exception to detect errors
    except socket.timeout: 
      print("Timeout")
    except ConnectionRefusedError:
      print("Refused to connect")

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
    try:
      #original request
      og_request = message.split('\r\n')
      #Request line == first line:
      first_line = og_request[0].split()
      method = first_line[0]
      if len(first_line) > 1:
        path = first_line[1]
      else:
        path ='/'
      if len(first_line) > 2:
        version = first_line[2]
      else:
        path='/'
      #Example:
       # Input: ['PUT', '/abc', 'HTTP/1.1'] → method='PUT', path='/abc', version='HTTP/1.1'
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      

      # Construct the request to send to the origin server
      request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode())
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      # Send response
      response = bytes() #empty variable to store bin response
      while chunk := originServerSocket.recv(BUFFER_SIZE):
        response += chunk
      clientSocket.sendall(response)
      #cache successful response only
      if method.upper() == 'GET' and response.startswith(b'HTTP/1.') and b' 200' in response.split(b'\r\n')[0]:
      # Create a new file in the cache for the requested file.
        cacheDir, file = os.path.split(cacheLocation)
        print ('cached directory ' + cacheDir)
        if not os.path.exists(cacheDir):
          os.makedirs(cacheDir)
        # Save origin server response in the cache file
      cacheFile = open(cacheLocation, 'wb')
      cacheFile.write(response)
      print('Response cache: ' + cacheLocation)
      cacheFile.close()
      print ('cache file closed')

      # finished communicating with origin server - shutdown socket writes
      print ('origin response received. Closing sockets')
      originServerSocket.close()
       
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')
    except OSError as err:
      print ('origin server request failed. ' + err.strerror)

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')
