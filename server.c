#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>

#define PORT 8080
#define BUFFER_SIZE 4096

void handle_client (int client_socket);
void send_response (int client_socket, const char* file_path);
char* get_mime_type (const char* path);
void log_request (const char* req_method, const char* req_path, bool is_malicious);
void url_decode_selected (char* src);

int server_fd, client_fd;
struct sockaddr_in server_addr, client_addr;
int s_addr_len = sizeof(server_addr);
int c_addr_len = sizeof(client_addr);

int main ()
{ 
    char* buffer[BUFFER_SIZE] = {0};
    int backlog = 10;

    //Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) 
    {
        perror("Failed to create socket!");
        return -1;
    }

    //Configure address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    //Bind the socket
    if (bind(server_fd, (struct sockaddr*)&server_addr, s_addr_len) < 0)
    {
        perror("Failed to bind socket!");
        return -1;
    }

    //Start listening for connection
    if (listen(server_fd, backlog) < 0)
    {
        perror("Failed to start listening for connection!");
        return -1;
    }

    printf("HTTP Server is listening on port %d...\n", PORT);

    while (1)
    {
        //Accept a client connection
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &c_addr_len);
        if (client_fd < 0)
        {
            perror("Failed to accept client!");
            continue;
        }

        printf("Received connection from client %s:%d.\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        //Send a simple response
        char* message = "You just connected to an HTTP server written in C.\n";
        send(client_fd, message, strlen(message), 0);

        //Handle the client request
        handle_client(client_fd);

        //Closes client connection
        close(client_fd);
        printf("Connection with client terminated!\n\n");
    }
    
    //Closes server socket when shutting down
    printf("\nShutting down the HTTP server!\n");
    close(server_fd);
    return 0;
}

//Function to handle client requests
void handle_client (int client_socket)
{
    char buffer[BUFFER_SIZE] = {0};

    int read_bytes = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (read_bytes <= 0)
    {
        perror("Failed to read the request!");
        return;
    }
    buffer[read_bytes] = '\0';
    printf("Received request:\n%s\n", buffer);
    
    //Extract method and requested file path
    char method[10] = {0}, path[256] = {0};
    sscanf(buffer, "%s %s", method, path);

    if (strstr(buffer, "../"))
    {
        char* message = "MALICIOUS FILE PATH DETECTED!\nDROPPING THE REQUEST!\n";
        send(client_socket, message, strlen(message), 0);
        printf("%sPath traversal attempt detected!\nCheck the logs!\n", message);
        log_request (method, path, true); //Save request to server logs
        return;
    }

    //URL decode the requested file path
    url_decode_selected(path);

    //Save request to server logs
    log_request (method, path, false);

    //Ensure we only handle GET requests
    if (strcmp(method, "GET") != 0)
    {
        char* message = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n";
        send(client_socket, message, strlen(message), 0);
        printf("Client didn't send GET request!\n");
        return;
    }

    // Default to serving "text.txt" if root is requested
    if (strcmp(path, "/") == 0)
    {
        strcpy(path, "/text.txt");
    }

    // Remove leading slash and prepend "www" directory
    char file_path[256] = "www";
    strcat(file_path, path);

    //Send the requested file
    send_response(client_socket, file_path);
}

//Function to send the requested file as HTTP response
void send_response (int client_socket, const char* file_path)
{
    int file_fd = open(file_path, O_RDONLY);
    if (file_fd == -1)
    {
        // Send 404 Not Found if the file does not exist
        char* response = "HTTP/1.1 404 Not Found\r\n"
                         "Content-Type: text/plain\r\n"
                         "Content-Length: 20\r\n\r\n"
                         "Can't find the file!\n";
        send(client_socket, response, strlen(response), 0);
        printf("Client requested non-existing file!\n");
        return;
    }

    //Determine file size
    struct stat file_stat;
    fstat(file_fd, &file_stat);
    size_t file_size = file_stat.st_size;

    //Determine Content-Type
    char* content_type = get_mime_type(file_path);

    //Send HTTP headers
    char header[256];
    sprintf(header, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\n\r\n", content_type, file_size);
    send(client_socket, header, strlen(header), 0);

    //Send file content
    char buffer[BUFFER_SIZE] = {0};
    ssize_t bytes_read;
    while ((bytes_read = read(file_fd, buffer, BUFFER_SIZE)) > 0)
    {
        send(client_socket, buffer, bytes_read, 0);
    }
    printf("File's content was successfully transffered to the client!\n");

    close(file_fd);
}

//Function to determine MIME type based on file extension
char* get_mime_type (const char* path)
{
    const char* ext = strrchr(path, '.'); //Find the last occurrence of '.'
    if (!ext || ext == path)
    {
        return "text/plain"; //Default MIME type if no extension is found
    }
    ext++; //Move past the '.'

    // Common MIME types mapping
    if (strcmp(ext, "html") == 0 || strcmp(ext, "htm") == 0) return "text/html";
    if (strcmp(ext, "css") == 0) return "text/css";
    if (strcmp(ext, "js") == 0) return "application/javascript";
    if (strcmp(ext, "json") == 0) return "application/json";
    if (strcmp(ext, "xml") == 0) return "application/xml";
    if (strcmp(ext, "txt") == 0) return "text/plain";
    if (strcmp(ext, "csv") == 0) return "text/csv";
    // Image types
    if (strcmp(ext, "jpeg") == 0 || strcmp(ext, "jpg") == 0) return "image/jpeg";
    if (strcmp(ext, "png") == 0) return "image/png";
    if (strcmp(ext, "gif") == 0) return "image/gif";
    if (strcmp(ext, "bmp") == 0) return "image/bmp";
    if (strcmp(ext, "svg") == 0) return "image/svg+xml";
    if (strcmp(ext, "ico") == 0) return "image/x-icon";
    if (strcmp(ext, "webp") == 0) return "image/webp";
    // Audio types
    if (strcmp(ext, "mp3") == 0) return "audio/mpeg";
    if (strcmp(ext, "wav") == 0) return "audio/wav";
    if (strcmp(ext, "ogg") == 0) return "audio/ogg";
    if (strcmp(ext, "aac") == 0) return "audio/aac";
    if (strcmp(ext, "flac") == 0) return "audio/flac";
    // Video types
    if (strcmp(ext, "mp4") == 0) return "video/mp4";
    if (strcmp(ext, "webm") == 0) return "video/webm";
    if (strcmp(ext, "ogg") == 0) return "video/ogg";
    if (strcmp(ext, "mov") == 0) return "video/quicktime";
    if (strcmp(ext, "avi") == 0) return "video/x-msvideo";
    if (strcmp(ext, "mkv") == 0) return "video/x-matroska";
    // Application types
    if (strcmp(ext, "pdf") == 0) return "application/pdf";
    if (strcmp(ext, "zip") == 0) return "application/zip";
    if (strcmp(ext, "tar") == 0) return "application/x-tar";
    if (strcmp(ext, "rar") == 0) return "application/vnd.rar";
    if (strcmp(ext, "7z") == 0) return "application/x-7z-compressed";
    if (strcmp(ext, "gz") == 0) return "application/gzip";
    if (strcmp(ext, "exe") == 0) return "application/x-msdownload";
    if (strcmp(ext, "wasm") == 0) return "application/wasm";

    return "text/plain"; //Default MIME type
}

//Function to save server logs
void log_request (const char* req_method, const char* req_path, bool is_malicious)
{
    FILE* log_file = fopen("server.log", "a");
    if (log_file)
    {
        if (is_malicious) fprintf(log_file, "Client: %s   Method: %s   Path: %s   <===== MALICIOUS REQUEST DETECTED!!!\n", inet_ntoa(client_addr.sin_addr), req_method, req_path);
        else fprintf(log_file, "Client: %s   Method: %s   Path: %s\n", inet_ntoa(client_addr.sin_addr), req_method, req_path);
        fclose(log_file);
    }
    else
    {
        perror("Failed to write to server.log!");
        exit(-1);
    }
}

//Function to URL decode the requested file path
void url_decode_selected(char* src) {
    char* dst = src;  // Modify in-place
    char a, b;

    while (*src) {
        if (*src == '%' && src[1] && src[2]) {
            a = src[1];
            b = src[2];

            // Decode only specific characters
            if ((a == '2' && b == '0') ||  // %20 → Space
                (a == '2' && b == 'F') ||  // %2F → /
                (a == '3' && b == 'A')) {  // %3A → :
                
                a = (a >= 'A') ? (a - 'A' + 10) : (a - '0');
                b = (b >= 'A') ? (b - 'A' + 10) : (b - '0');
                *dst++ = (a << 4) | b;
                src += 3;  // Move past %XX
            } else {
                // Keep % encoding untouched for other characters
                *dst++ = *src++;
            }
        } else if (*src == '+') {
            *dst++ = ' ';  // Convert `+` to space
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';  // Null-terminate the output string
}

