#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/time.h>

#define PORT 8080

// Magic GUID from the WebSocket protocol spec
static const char *WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// Base64 encoding (OpenSSL's EVP_EncodeBlock)
#include <openssl/evp.h>
static void base64_encode(const unsigned char *input, int length, char *output) {
    EVP_EncodeBlock((unsigned char*)output, input, length);
}

static void rtrim(char *s) {
    int end = (int)strlen(s) - 1;
    while (end >= 0 && isspace((unsigned char)s[end])) {
        s[end] = '\0';
        end--;
    }
}

static const char* get_header_value(const char* request, const char* header) {
    static char value[256];
    value[0] = '\0';
    char *pos = strcasestr((char*)request, header);
    if (pos) {
        pos += strlen(header);
        while (*pos && isspace((unsigned char)*pos)) pos++;
        char *end = strchr(pos, '\r');
        if (!end) end = strchr(pos, '\n');
        if (end) {
            int len = (int)(end - pos);
            if (len > 255) len = 255;
            strncpy(value, pos, len);
            value[len] = '\0';
            rtrim(value);
        }
    }
    return value[0] ? value : NULL;
}

static int do_handshake(int client_fd) {
    char buffer[2048];
    int n = recv(client_fd, buffer, sizeof(buffer)-1, 0);
    if (n <= 0) return -1;
    buffer[n] = '\0';

    if (strstr(buffer, "Upgrade: websocket") == NULL || strstr(buffer, "Connection: Upgrade") == NULL) {
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, resp, strlen(resp), 0);
        return -1;
    }

    const char *key = get_header_value(buffer, "Sec-WebSocket-Key:");
    if (!key) {
        const char *resp = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_fd, resp, strlen(resp), 0);
        return -1;
    }

    char combined[256];
    snprintf(combined, sizeof(combined), "%s%s", key, WS_GUID);

    unsigned char sha[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)combined, strlen(combined), sha);

    char accept_val[256];
    base64_encode(sha, SHA_DIGEST_LENGTH, accept_val);

    char response[512];
    snprintf(response, sizeof(response),
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n",
             accept_val);

    send(client_fd, response, strlen(response), 0);

    return 0;
}

static int read_frame(int fd, unsigned char *buf, size_t bufsize, bool *is_text, bool *is_close) {
    unsigned char header[2];
    int n = recv(fd, header, 2, 0);
    if (n <= 0) return -1;

    bool fin = (header[0] & 0x80) != 0;
    unsigned char opcode = header[0] & 0x0F;
    bool masked = (header[1] & 0x80) != 0;
    uint64_t payload_len = header[1] & 0x7F;

    if (opcode == 0x8) {
        *is_close = true;
        return 0;
    }

    *is_text = (opcode == 0x1);

    if (payload_len == 126) {
        unsigned char ext[2];
        if (recv(fd, ext, 2, 0) != 2) return -1;
        payload_len = (ext[0] << 8) | ext[1];
    } else if (payload_len == 127) {
        unsigned char ext[8];
        if (recv(fd, ext, 8, 0) != 8) return -1;
        payload_len = 0;
        for (int i = 0; i < 8; i++) {
            payload_len = (payload_len << 8) | ext[i];
        }
    }

    unsigned char mask_key[4];
    if (masked) {
        if (recv(fd, mask_key, 4, 0) != 4) return -1;
    }

    if (payload_len > bufsize) {
        return -1;
    }

    if (payload_len > 0) {
        int r = recv(fd, buf, (int)payload_len, 0);
        if (r != (int)payload_len) return -1;
        if (masked) {
            for (uint64_t i = 0; i < payload_len; i++) {
                buf[i] = buf[i] ^ mask_key[i % 4];
            }
        }
    }

    if (*is_text && payload_len < bufsize) {
        buf[payload_len] = '\0';
    }

    return (int)payload_len;
}

static int send_text_frame(int fd, const unsigned char *msg, size_t len) {
    unsigned char header[2];
    header[0] = 0x81;
    header[1] = (unsigned char)len;

    if (send(fd, header, 2, 0) != 2) return -1;
    if (len > 0 && send(fd, msg, len, 0) != (int)len) return -1;
    return 0;
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(1);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1);
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen");
        exit(1);
    }

    printf("WebSocket server listening on port %d\n", PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        printf("Client connected\n");

        if (do_handshake(client_fd) < 0) {
            close(client_fd);
            continue;
        }
        printf("Handshake complete. Upgraded to WebSocket.\n");

        fd_set readfds;
        unsigned char buffer[4096];

        while (1) {
            FD_ZERO(&readfds);
            FD_SET(client_fd, &readfds);

            int ret = select(client_fd+1, &readfds, NULL, NULL, NULL);
            if (ret < 0) {
                perror("select");
                break;
            }

            if (FD_ISSET(client_fd, &readfds)) {
                bool is_text = false;
                bool is_close = false;
                int len = read_frame(client_fd, buffer, sizeof(buffer)-1, &is_text, &is_close);
                if (len < 0) {
                    printf("Error reading frame, closing.\n");
                    break;
                }
                if (is_close) {
                    printf("Close frame received, closing connection.\n");
                    break;
                }

                if (is_text) {
                    printf("Received message: %s\n", buffer);
                    // Echo back
                    if (send_text_frame(client_fd, buffer, len) < 0) {
                        printf("Error sending frame, closing.\n");
                        break;
                    }
                } else {
                }
            }
        }

        close(client_fd);
        printf("Client disconnected\n");
    }

    close(server_fd);
    return 0;
}
