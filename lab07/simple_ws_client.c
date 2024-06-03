#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <stdint.h>

#define SEC_WEBSOCKET_KEY "erPKMz5t9vwqkJI+RmHnLw==" // use this fixed key or generate one
#define BUFFER_SIZE 1024

typedef struct wsframe {
    uint8_t fin:1;
    uint8_t rsv1:1;
    uint8_t rsv2:1;
    uint8_t rsv3:1;
    uint8_t opcode:4;
    uint8_t mask:1;
    uint8_t payload_len:7;
    uint16_t extended_payload_len;
    uint64_t more_extended_payload_len;
    uint8_t masking_key[4];
    uint8_t *data;
} wsframe_t;

// Helper function to convert 64-bit value to network byte order
uint64_t htonll(uint64_t value) {
    if (htonl(1) != 1) {
        return ((uint64_t)htonl(value & 0xFFFFFFFF) << 32) | htonl(value >> 32);
    }
    return value;
}

int build_ws_frame(wsframe_t *frame, size_t msg_len, size_t pl_len, const char *msg) 
{
    frame->fin = 1;
    frame->rsv1 = 0;
    frame->rsv2 = 0;
    frame->rsv3 = 0;
    frame->opcode = 0x1; // text frame
    frame->mask = 1;
    frame->payload_len = msg_len;
    if (msg_len == 126) {
        frame->extended_payload_len = htons(pl_len);
    } else if (msg_len == 127) {
        frame->more_extended_payload_len = htonll(pl_len);
    }

    srand((unsigned int)time(NULL));
    for (int i = 0; i < 4; i++) {
        // frame->masking_key[i] = rand() % 256;
        frame->masking_key[i] = i % 256;
        printf("%x ", frame->masking_key[i]);
    }
    printf("\n");

    frame->data = (uint8_t *)malloc(pl_len);
    for (size_t i = 0; i < pl_len; i++) {
        frame->data[i] = msg[i] ^ frame->masking_key[i % 4];
    }

    return 0;
}

int send_ws_frame(int sd, wsframe_t *frame, size_t pl_len) 
{
    uint8_t *hdr;
    size_t hdr_len = 2 + 4 + pl_len;
    size_t cur_pos = 0;

    if (frame->payload_len == 126) {
        hdr_len += 2;
    } else if (frame->payload_len == 127) {
        hdr_len += 8;
    } 

    printf("hdr length: %d\n", hdr_len);
    hdr = (uint8_t *)malloc(hdr_len);

    hdr[cur_pos++] = (frame->fin << 7) | (frame->rsv1 << 6) | (frame->rsv2 << 5) | (frame->rsv3 << 4) | (frame->opcode);
    hdr[cur_pos++] = (frame->mask << 7) | (frame->payload_len);

    if (frame->payload_len == 126) {
        uint16_t len = frame->extended_payload_len;
        memcpy(hdr + cur_pos, &len, 2);
        cur_pos += 2;
    } else if (frame->payload_len == 127) {
        uint64_t len = frame->more_extended_payload_len;
        memcpy(hdr + cur_pos, &len, 8);
        cur_pos += 8;
    }

    memcpy(hdr + cur_pos, frame->masking_key, 4);
    cur_pos += 4;
    memcpy(hdr + cur_pos, frame->data, pl_len);

    for (int i = 0; i < hdr_len; i++) {
        printf("%x ", hdr[i]);
    }
    printf("\n");

    int send_byte;
    if ((send_byte = send(sd, hdr, hdr_len, 0)) < 1) {
        perror("send frame");
        free(hdr);
        exit(EXIT_FAILURE);
    }

    return 0;
}

int main(int argc, char *argv[]) {
    
    // Declare variables 
    char buffer[BUFFER_SIZE];

    // Check command line arguments.
    if(argc != 4)
    {
        printf("Usage: %s <host> <port> <text>\n"  \
               "Example: \n" \
               "        %s 192.168.10.25 8080 \'Hello, world!\'\n", argv[0], argv[0]); 
        return -1;
    }

    // Get message
    size_t msg_len, pl_len;
    msg_len = strlen(argv[3]);
    printf("message length: %d\n", msg_len);
    if (msg_len < 126) {
        pl_len = msg_len;
    } else if (msg_len < 65536) {
        pl_len = msg_len;
        msg_len = 126;
    } else {
        pl_len = msg_len;
        msg_len = 127;
    }
    char *msg = (char *)malloc(pl_len + 1);
    memcpy(msg, argv[3], pl_len);
    msg[pl_len] = '\0';

    // Connect to host 
    int sd = socket(PF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in serv_adr;
    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_adr.sin_port = htons(atoi(argv[2]));
    connect(sd, (struct sockaddr*)&serv_adr, sizeof(serv_adr));

    puts("Connected...\n");

    // Send WebSocket handshake request
    char *request = "GET %s HTTP/1.1\r\n"
                    "Host: %s:%d\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Key: %s\r\n"
                    "Sec-WebSocket-Version: 13\r\n"
                    "\r\n";                    
    sprintf(buffer, request, argv[1], argv[1], atoi(argv[2]), SEC_WEBSOCKET_KEY);
    
    int send_byte;
    if ((send_byte = send(sd, buffer, sizeof(buffer), 0)) < 0) {
        perror("send error");
        exit(EXIT_FAILURE);
    }
    puts("Opening handshake sent...\n");

    // Wait for HTTP response from server
    memset(buffer, 0, BUFFER_SIZE);
    int read_byte;
    if ((read_byte = read(sd, buffer, BUFFER_SIZE)) < 0) {
        perror("read error");
        exit(EXIT_FAILURE);
    }

    puts("Received...\n");
    printf("%s\n", buffer);

    // Verify accept key -> no need to implement 

    // Send WebSocket message   
    wsframe_t frame;
    build_ws_frame(&frame, msg_len, pl_len, msg);
    send_ws_frame(sd, &frame, pl_len);
    puts("WebSocket message sent...\n");

    // Wait for echo response message from server
    memset(buffer, 0, BUFFER_SIZE);
    printf("buffer check up: %s\n", buffer);
    if ((read_byte = read(sd, buffer, BUFFER_SIZE)) < 0) {
        perror("read error");
        exit(EXIT_FAILURE);
    }
    printf("buffer check down: %s\n", buffer);
    
    // Send close frame: Close code = 1000 
    // Close code must be converted to network byte order via htons() 
    
    // Receive close response from server 
    

    // Close socket descriptor
    free(msg);
    free(frame.data);

    close(sd);

    return 0;
}
