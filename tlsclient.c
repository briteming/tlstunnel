#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>
#include <errno.h>

#define KEY            "98kNLBdIphvpD9tl6NGZnTIUIh2rU2Km"
#define MAX_EVENT      1024
#define MAX_CONNECT    1024

#define MAXDATASIZE    2*1024*1024
#define KEEPALIVE            // 如果定义了，就是启动心跳包，不定义就不启动，下面3个参数就没有意义。
#define KEEPIDLE       60    // tcp完全没有数据传输的最长间隔为60s，操过60s就要发送询问数据包
#define KEEPINTVL      3     // 如果询问失败，间隔多久再次发出询问数据包
#define KEEPCNT        1     // 连续多少次失败断开连接

typedef enum {
    DISCONNECT,
    UNWATCH,
    UNREGISTER,
    TLSUNREADY,
    WAITRETURN,
    REGISTER,
} STATUS;

struct FDCLIENT {
    int fd;
    SSL *tls;
    STATUS status;
    int canwrite;
    char* data;
    unsigned int datasize;
    unsigned int fullsize;
    struct FDCLIENT* outclient;
};
struct FDCLIENT *remainfdclienthead = NULL;
static int epollfd;
SSL_CTX *ctx;
unsigned char serverip[4] = {192, 168, 56, 101};

int setsocketoption (int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        printf("get flags fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        printf("set flags fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -2;
    }
    unsigned int socksval = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (unsigned char*)&socksval, sizeof(socksval))) { // 关闭Nagle协议
        printf("close Nagle protocol fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -3;
    }
#ifdef KEEPALIVE
    socksval = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (unsigned char*)&socksval, sizeof(socksval))) { // 启动tcp心跳包
        printf("set socket keepalive fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -4;
    }
    socksval = KEEPIDLE;
    if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepidle fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -5;
    }
    socksval = KEEPINTVL;
    if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepintvl fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -6;
    }
    socksval = KEEPCNT;
    if (setsockopt(fd, SOL_TCP, TCP_KEEPCNT, (unsigned char*)&socksval, sizeof(socksval))) { // 设置tcp心跳包参数
        printf("set socket keepcnt fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        close(fd);
        return -7;
    }
#endif
    // 修改发送缓冲区大小
    socklen_t socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -8;
    }
    printf("old send buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    socksval = MAXDATASIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, sizeof (socksval))) {
        printf("set send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -9;
    }
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get send buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -10;
    }
    printf("new send buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    // 修改接收缓冲区大小
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -11;
    }
    printf("old receive buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    socksval = MAXDATASIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char*)&socksval, sizeof(socksval))) {
        printf("set receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -12;
    }
    socksval_len = sizeof(socksval);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (unsigned char*)&socksval, &socksval_len)) {
        printf("get receive buffer fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -13;
    }
    printf("new receive buffer is %d, socksval_len:%d, fd:%d, in %s, at %d\n", socksval, socksval_len, fd,  __FILE__, __LINE__);
    return 0;
}

int addtoepoll (struct FDCLIENT *fdclient, uint32_t flags) {
    struct epoll_event ev;
    ev.data.ptr = fdclient;
    ev.events = EPOLLERR | EPOLLHUP | EPOLLRDHUP | flags; // 水平触发，保证所有数据都能读到
    return epoll_ctl(epollfd, EPOLL_CTL_ADD, fdclient->fd, &ev);
}

int modepoll (struct FDCLIENT *fdclient, uint32_t flags) {
    struct epoll_event ev;
    ev.data.ptr = fdclient;
    ev.events = EPOLLERR | EPOLLHUP | EPOLLRDHUP | flags; // 水平触发，保证所有数据都能读到
    return epoll_ctl(epollfd, EPOLL_CTL_MOD, fdclient->fd, &ev);
}

int create_socketfd (unsigned short port) {
    struct sockaddr_in sin;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("run socket function is fail, fd:%d, in %s, at %d\n", fd, __FILE__, __LINE__);
        return -1;
    }
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET; // ipv4
    sin.sin_addr.s_addr = INADDR_ANY; // 本机任意ip
    sin.sin_port = htons(port);
    if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        printf("bind port %d fail, fd:%d, in %s, at %d\n", port, fd, __FILE__, __LINE__);
        close(fd);
        return -2;
    }
    if (listen(fd, MAX_CONNECT) < 0) {
        printf("listen port %d fail, fd:%d, in %s, at %d\n", port, fd, __FILE__, __LINE__);
        close(fd);
        return -3;
    }
    int val = 6;
    if (setsockopt(fd, SOL_TCP, TCP_DEFER_ACCEPT, &val, sizeof(val))) {
        printf("set fd defer accept fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        close(fd);
        return -4;
    }
    struct FDCLIENT* fdserver;
    if (remainfdclienthead) { // 有存货，直接拿出来用
        fdserver = remainfdclienthead;
        remainfdclienthead = remainfdclienthead->outclient;
    } else { // 没有存货，malloc一个
        fdserver = (struct FDCLIENT*) malloc(sizeof(struct FDCLIENT));
        if (fdserver == NULL) {
            printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
            close(fd);
            return -5;
        }
        fdserver->data = NULL;
        fdserver->fullsize = 0;
    }
    fdserver->fd = fd;
    fdserver->tls = NULL;
    fdserver->status = REGISTER;
    fdserver->canwrite = 1;
    fdserver->datasize = 0;
    fdserver->outclient = NULL;
    if (addtoepoll(fdserver, EPOLLIN)) {
        printf("serverfd add to epoll fail, fd:%d, in %s, at %d\n", fd,  __FILE__, __LINE__);
        fdserver->status = DISCONNECT;
        fdserver->outclient = remainfdclienthead;
        remainfdclienthead = fdserver;
        return -6;
    }
    return fd;
}

int removeclient (struct FDCLIENT* fdclient) {
    if (fdclient->status == DISCONNECT) {
        return 0;
    }
    if (fdclient->status != UNWATCH) {
        epoll_ctl(epollfd, EPOLL_CTL_DEL, fdclient->fd, NULL);
    }
    fdclient->outclient = remainfdclienthead;
    remainfdclienthead = fdclient;
    if (fdclient->tls) {
        SSL_shutdown(fdclient->tls);
        SSL_free(fdclient->tls);
    }
    close(fdclient->fd);
    fdclient->status = DISCONNECT;
    return 0;
}

int writenode (struct FDCLIENT* fdclient, const char* data, unsigned int size) {
    ssize_t len;
    if (!fdclient->canwrite) {
        printf("in %s, at %d\n"__FILE__, __LINE__);
        unsigned int datasize = fdclient->datasize + datasize;
        if (datasize > fdclient->fullsize) {
            if (fdclient->fullsize > 0) {
                free(fdclient->data);
            }
            fdclient->data = (char*)malloc(datasize);
            if (fdclient->data == NULL) {
                perror("malloc fail");
                printf("size: %d, errno:%d, in %s, at %d\n", datasize, errno,  __FILE__, __LINE__);
                return -1;
            }
            fdclient->fullsize = datasize;
        }
        memcpy(fdclient->data + fdclient->datasize, data, datasize);
        fdclient->datasize = datasize;
        return 0;
    }
    static char* tmp_data = NULL;
    static unsigned int tmp_size = 0;
    unsigned int datasize = fdclient->datasize + size;
    if (datasize > tmp_size) {
        if (tmp_size > 0) {
            free(tmp_data);
        }
        tmp_data = (char*)malloc(datasize);
        if (tmp_data == NULL) {
            perror("malloc fail");
            printf("size: %d, errno:%d, in %s, at %d\n", datasize, errno,  __FILE__, __LINE__);
            return -2;
        }
        tmp_size = datasize;
    }
    if (fdclient->datasize > 0) {
        memcpy(tmp_data, fdclient->data, fdclient->datasize);
    }
    memcpy(tmp_data + fdclient->datasize, data, size);
    if (fdclient->tls) {
        len = SSL_write(fdclient->tls, tmp_data, datasize);
    } else {
        len = write(fdclient->fd, tmp_data, datasize);
    }
    if (len < datasize) {
        if (len < 0) {
            if (errno != EAGAIN) {
                perror("write error");
                printf("fd:%d, errno:%d, in %s, at %d\n", fdclient->fd, errno,  __FILE__, __LINE__);
                return -3;
            }
            len = 0;
        }
        unsigned int ramainsize = datasize - len;
        if (ramainsize > fdclient->fullsize) {
            if (fdclient->fullsize > 0) {
                free(fdclient->data);
            }
            fdclient->data = (char*)malloc(ramainsize);
            if (fdclient->data == NULL) {
                perror("malloc fail");
                printf("size: %d, errno:%d, in %s, at %d\n", ramainsize, errno,  __FILE__, __LINE__);
                return -4;
            }
            fdclient->fullsize = ramainsize;
        }
        memcpy(fdclient->data, tmp_data + len, ramainsize);
        fdclient->datasize = ramainsize;
        if (modepoll(fdclient, EPOLLIN | EPOLLOUT)) {
            perror("write error");
            printf("fd:%d, errno:%d, in %s, at %d\n", fdclient->fd, errno,  __FILE__, __LINE__);
            return -5;
        }
        fdclient->canwrite = 0;
        return 0;
    }
    fdclient->datasize = 0;
    return 0;
}

int writedata (struct FDCLIENT* fdclient) {
    if (fdclient->datasize > 0) {
        ssize_t len;
        if (fdclient->tls) {
            len = SSL_write(fdclient->tls, fdclient->data, fdclient->datasize);
        } else {
            len = write(fdclient->fd, fdclient->data, fdclient->datasize);
        }
        if (len < fdclient->datasize) {
            if (len < 0) {
                if (errno != EAGAIN) {
                    perror("write error");
                    printf("fd:%d, errno:%d, in %s, at %d\n", fdclient->fd, errno,  __FILE__, __LINE__);
                    struct FDCLIENT* outclient = fdclient->outclient;
                    removeclient(fdclient);
                    removeclient(outclient);
                    return -1;
                }
                return 0;
            }
            unsigned int datasize = fdclient->datasize - len;
            if (datasize > fdclient->fullsize) {
                if (fdclient->fullsize > 0) {
                    free(fdclient->data);
                }
                fdclient->data = (char*)malloc(datasize);
                fdclient->fullsize = datasize;
            }
            memcpy(fdclient->data, fdclient->data + len, fdclient->datasize - len);
            fdclient->datasize = datasize;
            return 0;
        }
    }
    if (modepoll(fdclient, EPOLLIN)) {
        perror("modify epoll error");
        printf("fd:%d, errno:%d, in %s, at %d\n", fdclient->fd, errno,  __FILE__, __LINE__);
        struct FDCLIENT* outclient = fdclient->outclient;
        removeclient(fdclient);
        removeclient(outclient);
        return -2;
    }
    fdclient->canwrite = 1;
    return 0;
}

int addclient (int acceptfd, unsigned short port) {
    struct sockaddr_in sin;
    socklen_t in_addr_len = sizeof(struct sockaddr_in);
    int infd = accept(acceptfd, (struct sockaddr*)&sin, &in_addr_len);
    if (infd < 0) {
        printf("create socket fd is fail, in %s, at %d\n", __FILE__, __LINE__);
        return -1;
    }
    if (setsocketoption(infd)) {
        printf("set fd to nonblocking fail, in %s, at %d\n", __FILE__, __LINE__);
        close(infd);
        return -2;
    }
    struct FDCLIENT* fdclient;
    if (remainfdclienthead) { // 有存货，直接拿出来用
        fdclient = remainfdclienthead;
        remainfdclienthead = remainfdclienthead->outclient;
    } else { // 没有存货，malloc一个
        fdclient = (struct FDCLIENT*) malloc(sizeof(struct FDCLIENT));
        if (fdclient == NULL) {
            printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
            close(infd);
            return -3;
        }
        fdclient->data = NULL;
        fdclient->fullsize = 0;
    }
    fdclient->fd = infd;
    fdclient->tls = NULL;
    fdclient->status = UNWATCH;
    fdclient->canwrite = 1;
    fdclient->datasize = 0;
    int outfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (outfd < 0) {
        printf("create socket fd is fail, in %s, at %d\n", __FILE__, __LINE__);
        removeclient(fdclient);
        return -4;
    }
    if (setsocketoption(outfd)) {
        printf("set fd to nonblocking fail, in %s, at %d\n", __FILE__, __LINE__);
        removeclient(fdclient);
        close(outfd);
        return -3;
    }
    struct FDCLIENT* fdserver;
    if (remainfdclienthead) { // 有存货，直接拿出来用
        fdserver = remainfdclienthead;
        remainfdclienthead = remainfdclienthead->outclient;
    } else { // 没有存货，malloc一个
        fdserver = (struct FDCLIENT*) malloc(sizeof(struct FDCLIENT));
        if (fdserver == NULL) {
            printf("malloc fail, in %s, at %d\n",  __FILE__, __LINE__);
            removeclient(fdclient);
            close(outfd);
            return -2;
        }
        fdserver->data = NULL;
        fdserver->fullsize = 0;
    }
    fdserver->fd = outfd;
    fdserver->status = UNWATCH;
    fdserver->canwrite = 1;
    fdserver->datasize = 0;
    fdserver->tls = NULL;
    fdclient->outclient = fdserver;
    fdserver->outclient = fdclient;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    memcpy(&sin.sin_addr, serverip, 4);
    if (connect(outfd, (struct sockaddr*)&sin, sizeof(struct sockaddr)) < 0) {
        if (errno != EINPROGRESS) {
            perror("tcp connect error");
            printf("errno:%d, in %s, at %d\n", errno, __FILE__, __LINE__);
            removeclient(fdclient);
            removeclient(fdserver);
            return -4;
        }
    }
    SSL *tls = SSL_new(ctx);
    SSL_set_fd(tls, outfd);
    fdserver->tls = tls;
    if (addtoepoll(fdserver, EPOLLOUT)) {
        printf("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        removeclient(fdclient);
        removeclient(fdserver);
        return -6;
    }
    fdserver->status = UNREGISTER;
}

int registerclient (struct FDCLIENT* fdserver) {
    if (writenode(fdserver, KEY, 32)) { // 这里就会自动启动读监听，不需要额外设置。
        printf("write node fail, in %s, at %d\n",  __FILE__, __LINE__);
        struct FDCLIENT* outclient = fdserver->outclient;
        removeclient(fdserver);
        removeclient(outclient);
        return -1;
    }
    fdserver->status = WAITRETURN;
    return 0;
}

int checkregisterdata (struct FDCLIENT* fdserver) {
    struct FDCLIENT* outclient = fdserver->outclient;
    char data[8];
    ssize_t len = SSL_read (fdserver->tls, data, sizeof(data));
    if (len <= 0) {
        if (errno == EAGAIN) {
            return 0;
        }
        perror("read error");
        printf("fd:%d, errno:%d, in %s, at %d\n", fdserver->fd, errno,  __FILE__, __LINE__);
        removeclient(fdserver);
        removeclient(outclient);
        return -1;
    }
    if (len > 1 || data[0] != 0x01) {
        printf("key check fail, len:%d, res:0x%02x, in %s, at %d\n", len, data[0],  __FILE__, __LINE__);
        removeclient(fdserver);
        removeclient(outclient);
        return -2;
    }
    fdserver->status = REGISTER;
    if (addtoepoll(outclient, EPOLLIN)) {
        printf("create epoll fd fail, fd:%d, in %s, at %d\n", outclient->fd,  __FILE__, __LINE__);
        removeclient(fdserver);
        removeclient(outclient);
        return -3;
    }
    outclient->status = REGISTER;
    return 0;
}

int copydata (struct FDCLIENT* inclient) {
    static char data[320*1024];
    struct FDCLIENT* outclient = inclient->outclient;
    ssize_t len;
    if (inclient->tls) {
        len = SSL_read(inclient->tls, data, sizeof(data));
    } else {
        len = read(inclient->fd, data, sizeof(data));
    }
    if (len < 0) {
        if (errno == EAGAIN) {
            return 0;
        }
        perror("read error");
        printf("fd:%d, errno:%d, in %s, at %d\n", inclient->fd, errno,  __FILE__, __LINE__);
        removeclient(inclient);
        removeclient(outclient);
        return -1;
    }
    if (writenode(outclient, data, len)) {
        perror("write node error");
        printf("fd:%d, errno:%d, in %s, at %d\n", outclient->fd, errno,  __FILE__, __LINE__);
        removeclient(inclient);
        removeclient(outclient);
        return -2;
    }
    return 0;
}

int main () {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    if(ctx == NULL) {
        printf("create SSL CTX fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -1;
    }
    if ((epollfd = epoll_create(MAX_EVENT)) < 0) {
        printf("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -2;
    }
    static int httpfd;
    httpfd = create_socketfd(1082);
    if (httpfd < 0) {
        printf("create http tun fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -3;
    }
    static int socks5fd;
    socks5fd = create_socketfd(1083);
    if (socks5fd < 0) {
        printf("create socks5 tun fail, in %s, at %d\n",  __FILE__, __LINE__);
        return -4;
    }
    printf("KEY: %s, in %s, at %d\n", KEY, __FILE__, __LINE__);
    printf("localip:1082 -> remoteip:8888, in %s, at %d\n", __FILE__, __LINE__);
    printf("localip:1083 -> remoteip:8889, in %s, at %d\n", __FILE__, __LINE__);
    while (1) {
        static struct epoll_event evs[MAX_EVENT];
        int wait_count = epoll_wait(epollfd, evs, MAX_EVENT, -1);
        for (int i = 0 ; i < wait_count ; i++) {
            struct FDCLIENT* fdclient = (struct FDCLIENT*)evs[i].data.ptr;
            uint32_t events = evs[i].events;
            if (fdclient->status == DISCONNECT) {
                ;
            } else if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                struct FDCLIENT *outclient = fdclient->outclient;
                removeclient(fdclient);
                removeclient(outclient);
            } else if (events & EPOLLIN) {
                if (fdclient->fd == httpfd) {
                    addclient(httpfd, 443);
                } else if (fdclient->fd == socks5fd) {
                    addclient(socks5fd, 8443);
                } else if (fdclient->status == UNREGISTER) { // 加密连接
                    int r_code = SSL_connect(fdclient->tls);
                    int errcode = SSL_get_error(fdclient->tls, r_code);
                    if (r_code < 0) {
                        if (errcode == SSL_ERROR_WANT_WRITE) { // 资源暂时不可用，write没有ready.
                            if (modepoll(fdclient, EPOLLOUT)) {
                                printf("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
                                struct FDCLIENT *outclient = fdclient->outclient;
                                removeclient(fdclient);
                                removeclient(outclient);
                            }
                        } else if (errcode != SSL_ERROR_WANT_READ) {
                            perror("tls connect error");
                            printf("errno:%d, errcode:%d, in %s, at %d\n", errno, errcode, __FILE__, __LINE__);
                            struct FDCLIENT *outclient = fdclient->outclient;
                            removeclient(fdclient);
                            removeclient(outclient);
                        }
                        continue;
                    }
                    registerclient(fdclient);
                } else if (fdclient->status == WAITRETURN) { // 等待key校验返回
                    checkregisterdata(fdclient);
                } else {
                    copydata(fdclient);
                }
            } else if (events & EPOLLOUT) {
                if (fdclient->status == UNREGISTER) { // 加密连接
                    int r_code = SSL_connect(fdclient->tls);
                    int errcode = SSL_get_error(fdclient->tls, r_code);
                    if (r_code < 0) {
                        if (errcode == SSL_ERROR_WANT_READ) { // 资源暂时不可用，read没有ready.
                            if (modepoll(fdclient, EPOLLIN)) {
                                printf("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
                                struct FDCLIENT *outclient = fdclient->outclient;
                                removeclient(fdclient);
                                removeclient(outclient);
                            }
                        } else if (errcode != SSL_ERROR_WANT_WRITE) {
                            perror("tls connect error");
                            printf("errno:%d, errcode:%d, in %s, at %d\n", errno, errcode, __FILE__, __LINE__);
                            struct FDCLIENT *outclient = fdclient->outclient;
                            removeclient(fdclient);
                            removeclient(outclient);
                        }
                        continue;
                    }
                    registerclient(fdclient);
                    if (modepoll(fdclient, EPOLLIN)) {
                        printf("create epoll fd fail, in %s, at %d\n",  __FILE__, __LINE__);
                        struct FDCLIENT *outclient = fdclient->outclient;
                        removeclient(fdclient);
                        removeclient(outclient);
                    }
                } else {
                    writedata(fdclient);
                }
            } else {
                printf("receive new event 0x%08x, in %s, at %d\n", events,  __FILE__, __LINE__);
            }
        }
    }
    SSL_CTX_free(ctx);
    return 0;
}
