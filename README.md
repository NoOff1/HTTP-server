# HTTP-server
Simple HTTP server written in C.

# Overview
This C-based HTTP server is a lightweight, single-threaded server that handles basic HTTP GET requests. It listens on a specified port (8080 by default), accepts client connections, processes their requests, and serves static files.

# How it works
1. The server listens for incoming TCP connections on PORT 8080.
2. When a client sends an HTTP request:
        The server parses the method and requested file.
        It blocks directory traversal attempts.
        It serves the requested file from the www/ folder.
3. Logs every request into server.log.

# Features
- Serves static files from the `www/` directory.
- Handles **GET requests** only.
- Supports **MIME type detection** (HTML, CSS, JS, images, audio, video, etc.).
- Implements **basic security** (blocks `../` path traversal attacks).
- Logs all client requests to `server.log`.

# Security features
- Path Traversal Prevention: Blocks requests containing ../ to prevent directory traversal attacks.
- Graceful Error Handling: Returns proper HTTP error codes like 404 Not Found.
- Basic URL Decoding: Decodes %20 (space), %2F (slash), and %3A (colon) in file paths.

# Components of the server
The server consists of the following key functions:
main(): Initializes the server, listens for connections, and handles clients.
handle_client(): Parses HTTP requests and determines the response.
send_response(): Reads requested files and sends them as HTTP responses.
get_mime_type(): Determines the MIME type of requested files.
log_request(): Logs all incoming HTTP requests.
url_decode_selected(): Decodes URL-encoded characters in file paths.

# Step-by-step execution
1. Create a TCP socket using socket().
2. Bind the socket to an IP and port (8080).
3. Start listening for incoming connections.
4. Accept incoming requests using accept().
5. Read the HTTP request, extract the method and file path.
6. Check for malicious path traversal (../).
7. Handle GET requests:
        If the path is /, serve a default file (text.txt).
        Remove leading / and add the www directory.
        Find the file and determine its MIME type.
        Send the file as an HTTP response.
8. Log each request for debugging and security.
9. Close the connection once the response is sent.
