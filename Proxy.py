# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
from urllib.parse import urlparse
import time

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
  try:
  # and store it in the variable: message_bytes
    message_bytes = clientSocket.recv(BUFFER_SIZE)
    if not message_bytes:
      print("Cannot receive msg from client")
      clientSocket.close()
      continue # skip to the next connection
    
    message = message_bytes.decode('utf-8') #store decoded msg converst bin to str
    print ('Received request:')
    print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
    requestParts = message.split()
    if len(requestParts) < 3:
      clientSocket.close()
      continue
    
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
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default' 

    print ('Cache location:\t\t' + cacheLocation)
    cache_allowed = True
    max_age=3600 #set as default
    
    for line in message.split('\r\n')[1:]:
      if ':' in line: #check if line contains a colon as header fields are in name: value
        key, value = line.split(':', 1) #split the header at the first colon, 1 = one split only. Example Cache-Control: no-cache --> key = "Cache-Control" and value = "no-cache"
        key = key.strip().lower 
        if key == 'cache-control':  #check if there is cache-control      
          if 'no-cache' in value.lower(): #if no-cache assgigned then no cache
            cache_allowed = False #change the flag
          break
        
      #check cached file if caching is allowed
      if cache_allowed and os.path.exists(cacheLocation):
        with open(cacheLocation, 'r') as file:
          for line in file:
            if line.lower().startswith('cache-control'):
              if 'no-store' in line.lower():
                cache_allowed = False
                break
              elif 'max-age' in line.lower(): #get max-age
                max_age_match = re.search(r'max-age=(\d+)', line.lower())
                if max_age_match:
                  max_age = int(max_age_match.group(1))
                break
      file_age = time.time() - os.path.getmtime(cacheLocation)
      if file_age > max_age:
        cache_allowed = False #chaneg the flag
        os.remove(cacheLocation)
            
      if cache_allowed and os.path.exists(cacheLocation):
        # Check wether the file is currently in the cache
        print ('Cache hit! Loading from cache file: ' + cacheLocation)
        cacheFile = open(cacheLocation, "r")
        cacheData = cacheFile.readlines() #alternative approach: cacheData = cacheFile.read() --> preserves exact HTTP response including headrs
        for line in cacheData:
          clientSocket.send(line) #can be sendall(cacheData) send all at once to inprove performance
        cacheFile.close()
        print ('Sent to the client:')
        print ('> ' + cacheData)
  except:
    # cache miss.  Get resource from origin 
    redirect_count = 0
    max_redirects = 3     
    # and store in originServerSocket
    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      originServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) #similar the previous socket: AF_INET = IPv4 and SOCK_STREAM for TCP connections
      address = socket.gethostbyname(hostname)
      # Connect to the origin server on defalut HTTP port which is port 80
      originServerSocket.connect((address,80)) #use 'address' variable to avoid double lookup
      print ('Connected to origin Server')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      # ~~~~ INSERT CODE ~~~~
      requestLines = message.split('\r\n')
      #first line - request line
      first_line = requestLines[0].split()
      method = first_line[0]
      if len(first_line) > 1:
        path = first_line[1] #path
      else:
        path ='/'
      if len(first_line) > 2:
        path = first_line[2] #version
      else:
        path ='HTTP/1.'
      originServerRequestHeader = "Host: " + hostname +'\r\n'
      originServerRequest = f"{method} {path} {version}"
      # ~~~~ END CODE INSERT ~~~~

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
      # ~~~~ INSERT CODE ~~~~
      response = b''#binary
      while True:
        data = originServerSocket.recv(BUFFER_SIZE)
        if not data:
          break
        response += data
      # ~~~~ END CODE INSERT ~~~~
      #turn the bin response to str
      response_str = response.decode('utf-8', errors='ignore')
      #Attempt to handle redirects 301 nan 302
      redirect_status = response_str.split('\r\n')[0]
      redirect_code = int(redirect_status.split()[1]) #split the [1] and convert into an inf
      redirect_no = 0
      redirect_max = 3
      if redirect_code in (301, 302):
        redirect +=1
        for line in response_str.split('\r\n')[1:]:
            if line.lower().startswith('location:'):
              new_location = line.split(':', 1)[1].strip()
              # Update hostname and resource for redirect
              if new_location.startswith('http'):
                  parsed = urlparse(new_location)
                  hostname = parsed.netloc
                  resource = parsed.path or '/'
              else:
                  resource = new_location
                  break
              originServerSocket.close()
              continue
            
      if redirect_status == 404:
        print("404 NOT FOUND")
        

      # Send the response to the client
      # ~~~~ INSERT CODE ~~~~
      clientSocket.sendall(response)
      # ~~~~ END CODE INSERT ~~~~

      # Create a new file in the cache for the requested file.
      cacheDir, file = os.path.split(cacheLocation)
      print ('cached directory ' + cacheDir)
      if not os.path.exists(cacheDir):
        os.makedirs(cacheDir)
      cacheFile = open(cacheLocation, 'wb')

      # Save origin server response in the cache file
      # ~~~~ INSERT CODE ~~~~
      cacheFile.write(response)
      # ~~~~ END CODE INSERT ~~~~
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