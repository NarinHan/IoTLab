/*  사용한 방법 : level-triggered
    이번 실습은 클라이언트가 단일 파일을 서버에 업로드하는 서비스를 구현하는 것으로, 비교적 단순하고 간단한 일이다.
    따라서 리소스 사용을 줄이는 것으로 성능을 고려할 때 많이 쓰이는 ET 모드보다
    단순한 이벤트 처리로 오류의 최소화, 개발 단순화를 달성할 수 있는 LT 모드를 선택했다.
*/

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUF_SIZE 512
#define EPOLL_SIZE 50

void error_handling(char* message);

int
main(int argc, char* argv[])
{
    int serv_sock, clnt_sock ;
    struct sockaddr_in serv_adr, clnt_adr ;
    socklen_t adr_sz ;
    
    struct epoll_event* ep_events ;
    struct epoll_event event ;
    int epfd, event_cnt ;

    if (argc != 2) {
        printf("Usage: %s <Port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    memset(&serv_adr, 0, sizeof(serv_adr));
    serv_adr.sin_family = AF_INET;
    serv_adr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_adr.sin_port = htons(atoi(argv[1]));

    if (bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr)) == -1)
        error_handling("bind() error");
    if (listen(serv_sock, 5) == -1)
        error_handling("listen() error");

    epfd = epoll_create(EPOLL_SIZE);
    ep_events = malloc(sizeof(struct epoll_event) * EPOLL_SIZE);

    event.events = EPOLLIN;
    event.data.fd = serv_sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, serv_sock, &event);

    char buf[BUF_SIZE] ;
    char filename[BUF_SIZE] ;
    int str_len, read_cnt = 0 ;
    FILE* fp_manager[EPOLL_SIZE] ;

    while (1) {
        event_cnt = epoll_wait(epfd, ep_events, EPOLL_SIZE, -1) ;
        if (event_cnt == -1) {
            puts("epoll_wait() error") ;
            break ;
        }
        puts("return epoll_wait") ;
        for (int i = 0; i < event_cnt; i++) {
            if (ep_events[i].data.fd == serv_sock) {
                adr_sz = sizeof(clnt_adr) ;
                clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_adr, &adr_sz) ;
                event.events = EPOLLIN ;
                event.data.fd = clnt_sock ;
                fp_manager[clnt_sock] = NULL ;
                epoll_ctl(epfd, EPOLL_CTL_ADD, clnt_sock, &event) ;
                printf("connected client: %d\n", clnt_sock) ;
            } else {
                str_len = read(ep_events[i].data.fd, buf, BUF_SIZE) ;
                if (str_len == 0) { // EOF
                    epoll_ctl(epfd, EPOLL_CTL_DEL, ep_events[i].data.fd, NULL) ;
                    if (fp_manager[ep_events[i].data.fd]) {
                        fclose(fp_manager[clnt_sock]) ;
                        printf("Succesfully received [%s] from client %d\n", filename, ep_events[i].data.fd) ;
                        write(ep_events[i].data.fd, "Thank you", 10) ; // send complete message to client
                    }
                    close(ep_events[i].data.fd) ;
                    break ;
                } else {
                    if (!fp_manager[clnt_sock]) {
                        // get length of file name
                        int filename_len ;
                        memcpy(&filename_len, buf, sizeof(int)) ;
                        printf("check : filename_len : %d\n", filename_len) ;
                       
                        // get file name
                        memcpy(&filename, buf + sizeof(int), filename_len) ;
                        filename[filename_len] = '\0' ;
                        printf("check : filename : %s\n", filename) ;
                        printf("check : left : %s\n", buf + sizeof(int) + filename_len) ;
                        
                        // open file
                        fp_manager[clnt_sock] = fopen(filename, "wb") ;
                        if (!fp_manager[clnt_sock]) {
                            perror("error creating file") ;
                            epoll_ctl(epfd, EPOLL_CTL_DEL, ep_events[i].data.fd, NULL) ;
                            close(ep_events[i].data.fd) ;
                            exit(EXIT_FAILURE) ;
                        }

                        // write to file what is left in the buffer after processing file name
                        fwrite((void *)buf + sizeof(int) + filename_len, 1, str_len - sizeof(int) - filename_len, fp_manager[clnt_sock]) ;
                    } else {
                        fwrite((void *)buf, 1, str_len, fp_manager[clnt_sock]) ;
                        printf("check : after fopen : %s", buf) ;
                    } 
                }
            }
        }
    }

    close(serv_sock);
    close(epfd) ;
    
    free(ep_events) ;
    
    return 0;
}

void
error_handling(char* message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}
