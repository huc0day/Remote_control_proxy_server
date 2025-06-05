/*
//架构特点：
//
‌//高效端口复用‌：单进程管理多监听端口
‌//灵活通信机制‌：通过全局客户端集合实现跨端口消息路由
‌//线程安全保证‌：互斥锁保护共享数据结构
‌//扩展性强‌：支持动态增删监听端口（通过信号驱动配置重载）
*/
//
//包含头文件
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//定义常量
#define MAX_CLIENTS                                 8192       //最大客户端连接数量
#define ERROR_CLIENT_SEND_CONNECTION_ID_CREATE      8192       //客户端与代理端之间请求通道连接对应的自增ID创建失败（错误码）
#define ERROR_CLIENT_RECEIVE_CONNECTION_ID_CREATE   8192       //客户端与代理端之间应答通道连接对应的自增ID创建失败（错误码）
#define CLIENTS_NODE_IS_TRUE                        1          //客户端节点有效
#define CLIENTS_NODE_IS_FALSE                       0          //客户端节点无效
#define CLIENTS_MAX_LISTEN_PORTS                    1          //代理端监听来自客户端连接的端口数量
#define CLIENTS_MAX_EVENTS                          8192       //客户端产生的事件最大数量
#define CLIENT_BUFFER_SIZE                         1048576     //代理端接收客户端请求数据的缓冲区大小
#define CURRENT_REQUEST_DATA_MAX_SIZE               10000      //当前请求数据包中正文数据块的大小最大值
#define CURRENT_REQUEST_DATA_FILLING_MAX_SIZE       10000      //当前请求数据包中填充数据块的大小最大值
#define MAX_SERVERS                                 8192       //最大服务端连接数量
#define ERROR_SERVER_SEND_ID                        8192       //服务端与代理端之间请求通道连接对应的自增ID创建失败（错误码）
#define ERROR_SERVER_RECEIVE_ID                     8192       //服务端与代理端之间应答通道连接对应的自增ID创建失败（错误码）
#define SERVERS_NODE_IS_TRUE                        1          //服务端节点有效
#define SERVERS_NODE_IS_FALSE                       0          //服务端节点无效
#define SERVERS_MAX_LISTEN_PORTS                    1          //代理端监听来自服务端连接的端口数量
#define SERVERS_MAX_EVENTS                          8192       //服务端产生的事件最大数量
#define SERVER_BUFFER_SIZE                         1048576     //代理端接收服务端请求数据的缓冲区大小
#define CURRENT_RESPONSE_DATA_MAX_SIZE              10000      //当前应答数据包中正文数据块的大小最大值
#define CURRENT_RESPONSE_DATA_FILLING_MAX_SIZE      10000      //当前应答数据包中填充数据块的大小最大值
#define MD5_STRING_SIZE                             32         //MD5字符串的空间大小（不包含'\0'字符）
#define HANDLE_TYPE_CLIENT_SEND                     10000001   //客户端发送信息处理模块
#define HANDLE_TYPE_CLIENT_RECEIVE                  10000002   //客户端接收信息处理模块
#define HANDLE_TYPE_SERVER_SEND                     10000003   //服务端发送信息处理模块
#define HANDLE_TYPE_SERVER_RECEIVE                  10000004   //服务端接收信息处理模块
//
//定义全局变量
//
// SSL上下文全局变量
SSL_CTX * ssl_ctx;

// HTTP响应模板
const char * http_response =
                   "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain\r\n"
                   "Connection: close\r\n\r\n"
                   "Hello from HTTP Server\n";

// HTTPS响应模板
const char * https_response =
                   "HTTP/1.1 200 OK\r\n"
                   "Content-Type: text/plain\r\n"
                   "Connection: close\r\n\r\n"
                   "Secure Hello from HTTPS Server\n";

// 其它响应模板
const char * other_response =
                   "[HANDSHAKE_SUCCESS]\r\n";

//客户端连接验证的MD5字符串
char                                     * client_header_md5_data                       = "07ada13ce405cb441ff09f30b5963139";
//
char                                     * server_header_md5_data                       = "07ada13ce405cb441ff09f30b5963139";


/* 核心数据结构 */
//
//客户端发送请求连接对应的信息
struct client_send_port_listener_info {
    int       proxy_server_listen_socket;
    uint16_t  proxy_server_listen_port;
    pthread_t proxy_server_listen_thread_id;
};
//客户端接收应答连接对应的信息
struct client_receive_port_listener_info {
    int       proxy_server_listen_socket;
    uint16_t  proxy_server_listen_port;
    pthread_t proxy_server_listen_thread_id;
};
//服务端发送请求连接对应的信息
struct server_send_port_listener_info {
    int       proxy_server_listen_socket;
    uint16_t  proxy_server_listen_port;
    pthread_t proxy_server_listen_thread_id;
};
//服务端接收应答连接对应的信息
struct server_receive_port_listener_info {
    int       proxy_server_listen_socket;
    uint16_t  proxy_server_listen_port;
    pthread_t proxy_server_listen_thread_id;
};

//客户端发送数据节点（客户端向代理端发送请求数据）
struct client_send_node {
    int                client_socket;        //当前节点的套接字标识
    unsigned long long internal_code;        //客户端内部CODE（代表当前客户端程序的标识）
    unsigned int       client_ip;            //当前节点的来源IP
    unsigned int       client_port;          //当前节点的来源端口
    pthread_t          client_thread_id;     //当前节点的线程ID
    int                is_vaild;             //当前节点是否有效
};
//客户端接收数据节点（代理端向客户端发送应答数据）
struct client_receive_node {
    int                client_socket;        //当前节点的套接字标识
    unsigned long long internal_code;        //客户端内部CODE（代表当前客户端程序的标识）
    unsigned int       client_ip;            //当前节点的来源IP
    unsigned int       client_port;          //当前节点的来源端口
    pthread_t          client_thread_id;     //当前节点的线程ID
    int                is_vaild;             //当前节点是否有效
};

//服务端发送数据节点（服务端向代理端发送应答数据）
struct server_send_node {
    int                server_socket;       //当前节点的套接字标识
    unsigned long long internal_code;       //服务端内部CODE（代表当前服务端程序的标识）
    unsigned int       server_ip;           //当前节点的来源IP
    unsigned int       server_port;         //当前节点的来源端口
    pthread_t          server_thread_id;    //当前节点的线程ID
    int                is_vaild;            //当前节点是否有效
};
//服务端接收数据节点（代理端向服务端发送请求数据）
struct server_receive_node {
    int                server_socket;       //当前节点的套接字标识
    unsigned long long internal_code;       //服务端内部CODE（代表当前服务端程序的标识）
    unsigned int       server_ip;           //当前节点的来源IP
    unsigned int       server_port;         //当前节点的来源端口
    pthread_t          server_thread_id;    //当前节点的线程ID
    int                is_vaild;            //当前节点是否有效
};

//客户端请求包 client to proxy
struct client_request_data {
    char               token[MD5_STRING_SIZE];                                              //认证密钥（TOKEN）
    unsigned long long internal_code;                                                       //8字节（客户端内部 CODE）
    unsigned long long type;                                                                //操作头类型（1、broadcast = 广播 ，2、unicast = 单播）
    unsigned long long time_stamp;                                                          //4字节（UNIX 时间戳）
    unsigned long long rand_number;                                                         //4字节（随机数）
    unsigned long long server_ip;                                                           //4字节（服务端 IP）
    unsigned long long server_port;                                                         //4字节（服务端 PORT）
    unsigned long long request_id;                                                          //8字节（客户端请求ID）
    unsigned long long request_data_size;                                                   //8字节（客户端请求数据大小）
    unsigned long long request_data_offset;                                                 //8字节（客户端请求数据偏移）
    unsigned long long current_request_data_size;                                           //8字节（当前分片数据大小）
    char               current_request_data[CURRENT_REQUEST_DATA_MAX_SIZE];                 //10000字节（当前分片数据）
    char               current_request_data_filling[CURRENT_REQUEST_DATA_FILLING_MAX_SIZE]; //10000字节（当前分片填充）
    char               end_flags[MD5_STRING_SIZE];                                          //8字节（当前分片结束标志）
};  //sizeof(struct client_request_data)

//代理端应答包 proxy to client
struct proxy_response_data {
    char               token[MD5_STRING_SIZE];                                               //认证密钥（TOKEN）
    unsigned long long internal_code;                                                        //8字节（服务端内部 CODE）
    unsigned long long type;                                                                 //操作头类型（1、broadcast = 广播 ，2、unicast = 单播）
    unsigned long long time_stamp;                                                           //4字节（UNIX 时间戳）
    unsigned long long rand_number;                                                          //4字节（随机数）
    unsigned long long server_ip;                                                            //4字节（服务端 IP）
    unsigned long long server_port;                                                          //4字节（服务端 PORT）
    unsigned long long internal_ip;                                                          //4字节（内网 IP）
    unsigned long long response_id;                                                          //8字节（代理端应答ID，对应客户端的请求ID）
    unsigned long long response_data_size;                                                   //8字节（代理端应答数据大小）
    unsigned long long response_data_offset;                                                 //8字节（代理端应答数据偏移）
    unsigned long long current_response_data_size;                                           //8字节（当前分片数据大小）
    char               current_response_data[CURRENT_REQUEST_DATA_MAX_SIZE];                 //10000字节（当前分片数据）
    char               current_response_data_filling[CURRENT_REQUEST_DATA_FILLING_MAX_SIZE]; //10000字节（当前分片填充）
    char               end_flags[MD5_STRING_SIZE];                                           //8字节（当前分片结束标志）
};  //sizeof(struct proxy_response_data)

//代理端请求包 proxy to server
struct proxy_request_data {
    char               token[MD5_STRING_SIZE];                                                //认证密钥（TOKEN）
    unsigned long long internal_code;                                                         //8字节（客户端内部 CODE）
    unsigned long long type;                                                                  //操作头类型（1、broadcast = 广播 ，2、unicast = 单播）
    unsigned long long time_stamp;                                                            //4字节（UNIX 时间戳）
    unsigned long long rand_number;                                                           //4字节（随机数）
    unsigned long long channel_id;                                                            //8字节（渠道号：客户端线程iD）
    unsigned long long request_id;                                                            //8字节（代理端请求ID，对应客户端请求ID）
    unsigned long long request_data_size;                                                     //8字节（代理端请求数据大小）
    unsigned long long request_data_offset;                                                   //8字节（代理端请求数据偏移）
    unsigned long long current_request_data_size;                                             //8字节（当前分片数据大小）
    char               current_request_data[CURRENT_RESPONSE_DATA_MAX_SIZE];                  //10000字节（当前分片数据）
    char               current_request_data_filling[CURRENT_RESPONSE_DATA_FILLING_MAX_SIZE];  //10000字节（当前分片填充）
    char               end_flags[MD5_STRING_SIZE];                                            //8字节（当前分片结束标志）
};  //sizeof(struct proxy_request_data)

//服务端应答包 server to proxy
struct server_response_data {
    char               token[MD5_STRING_SIZE];                                                //认证密钥（TOKEN）
    unsigned long long internal_code;                                                         //8字节（服务端内部 CODE）
    unsigned long long type;                                                                  //操作头类型（1、broadcast = 广播 ，2、unicast = 单播）
    unsigned long long time_stamp;                                                            //4字节（UNIX 时间戳）
    unsigned long long rand_number;                                                           //4字节（随机数）
    unsigned long long internal_ip;                                                           //4字节（内网IP）
    unsigned long long channel_id;                                                            //8字节（渠道号：客户端线程iD）
    unsigned long long response_id;                                                           //8字节（服务端应答ID，对应客户端请求ID）
    unsigned long long response_data_size;                                                    //8字节（服务端应答数据大小）
    unsigned long long response_data_offset;                                                  //8字节（服务端应答数据偏移）
    unsigned long long current_response_data_size;                                            //8字节（当前分片数据大小）
    char               current_response_data[CURRENT_RESPONSE_DATA_MAX_SIZE];                 //10000字节（当前分片数据）
    char               current_response_data_filling[CURRENT_RESPONSE_DATA_FILLING_MAX_SIZE]; //10000字节（当前分片填充）
    char               end_flags[MD5_STRING_SIZE];                                            //8字节（当前分片结束标志）
};  //sizeof(struct server_response_data)
//
//
//
//8080端口接收来自客户端的指令
uint16_t                                 client_send_ports[CLIENTS_MAX_LISTEN_PORTS]    = { 8080 };
//
//8443端口将服务端的指令执行结果转发到客户端
uint16_t                                 client_receive_ports[CLIENTS_MAX_LISTEN_PORTS] = { 8443 };
//
//80端口发送客户端指令到服务端
uint16_t                                 server_send_ports[SERVERS_MAX_LISTEN_PORTS]    = { 80 };
//
//443端口接收来服务端的客户端指令执行结果
uint16_t                                 server_receive_ports[SERVERS_MAX_LISTEN_PORTS] = { 443 };
//
//
//代理端与客户端之间请求通道连接对应的监听实例数组（客户端向代理端发送请求）
struct client_send_port_listener_info    client_send_port_listeners[CLIENTS_MAX_LISTEN_PORTS];
//
//代理端与客户端之间应答通道连接对应的监听实例数组（代理端向客户端发送应答）
struct client_receive_port_listener_info client_receive_port_listeners[CLIENTS_MAX_LISTEN_PORTS];
//
//代理端与服务端之间请求通道连接对应的监听实例数组（代理端向服务端发送请求）
struct server_send_port_listener_info    server_send_port_listeners[SERVERS_MAX_LISTEN_PORTS];
//
//代理端与服务端之间应答通道连接对应的监听实例数组（服务端向代理端发送应答）
struct server_receive_port_listener_info server_receive_port_listeners[SERVERS_MAX_LISTEN_PORTS];
//
//
//客户端发送请求的连接节点列表
struct client_send_node                  client_send_nodes[MAX_CLIENTS];
//
//客户端接收应答的连接节点列表
struct client_receive_node               client_receive_nodes[MAX_CLIENTS];
//
//服务端接收请求的连接节点列表
struct server_send_node                  server_send_nodes[MAX_SERVERS];
//
//服务端发送应答的连接节点列表
struct server_receive_node               server_receive_nodes[MAX_SERVERS];
//
//
// 静态变量：线程安全的自增ID
static unsigned long long                client_send_next_id                            = 0;           // 初始值为0
static pthread_mutex_t                   client_send_id_mutex                           = PTHREAD_MUTEX_INITIALIZER;  // 静态初始化互斥锁
//
// 静态变量：线程安全的自增ID
static unsigned long long                client_receive_next_id                         = 0;           // 初始值为0
static pthread_mutex_t                   client_receive_id_mutex                        = PTHREAD_MUTEX_INITIALIZER;  // 静态初始化互斥锁
//
// 静态变量：线程安全的自增ID
static unsigned long long                server_send_next_id                            = 0;           // 初始值为0
static pthread_mutex_t                   server_send_id_mutex                           = PTHREAD_MUTEX_INITIALIZER;  // 静态初始化互斥锁
//
// 静态变量：线程安全的自增ID
static unsigned long long                server_receive_next_id                         = 0;           // 初始值为0
static pthread_mutex_t                   server_receive_id_mutex                        = PTHREAD_MUTEX_INITIALIZER;  // 静态初始化互斥锁
//
// 静态变量：线程安全的互斥锁
static pthread_mutex_t                   client_send_listeners_mutex                    = PTHREAD_MUTEX_INITIALIZER;  // 静态初始化互斥锁
static pthread_mutex_t                   client_receive_listeners_mutex                 = PTHREAD_MUTEX_INITIALIZER;  // 静态初始化互斥锁
//
// 静态变量：线程安全的互斥锁
static pthread_mutex_t                   server_send_listeners_mutex                    = PTHREAD_MUTEX_INITIALIZER;  // 静态初始化互斥锁
static pthread_mutex_t                   server_receive_listeners_mutex                 = PTHREAD_MUTEX_INITIALIZER;  // 静态初始化互斥锁
//
// 静态变量：线程安全的互斥锁
static pthread_mutex_t                   client_send_nodes_mutex                        = PTHREAD_MUTEX_INITIALIZER;  // 静态初始化互斥锁
static pthread_mutex_t                   client_receive_nodes_mutex                     = PTHREAD_MUTEX_INITIALIZER;  // 静态初始化互斥锁
//
// 静态变量：线程安全的互斥锁
static pthread_mutex_t                   server_send_nodes_mutex                        = PTHREAD_MUTEX_INITIALIZER;  // 静态初始化互斥锁
static pthread_mutex_t                   server_receive_nodes_mutex                     = PTHREAD_MUTEX_INITIALIZER;  // 静态初始化互斥锁
//
//函数原型声明（添加客户端和代理端之间的指令发送通道连接节点）
int add_client_send_node ( int client_send_socket ,
                           unsigned long long internal_code ,
                           unsigned int client_send_ip ,
                           unsigned int client_send_port ,
                           pthread_t client_send_thread_id );

//函数原型声明（添加客户端和代理端之间的指令执行结果接收通道连接节点）
int add_client_receive_node ( int client_receive_socket ,
                              unsigned long long internal_code ,
                              unsigned int client_receive_ip ,
                              unsigned int client_receive_port ,
                              pthread_t client_receive_thread_id );

//函数原型声明（添加代理端和服务端之间的指令发送通道连接节点）
int add_server_send_node ( int server_send_socket ,
                           unsigned long long internal_code ,
                           unsigned int server_send_ip ,
                           unsigned int server_send_port ,
                           pthread_t server_send_thread_id );

//函数原型声明（添加代理端和服务端之间的指令执行结果接收通道连接节点）
int add_server_receive_node ( int server_receive_socket ,
                              unsigned long long internal_code ,
                              unsigned int server_receive_ip ,
                              unsigned int server_receive_port ,
                              pthread_t server_receive_thread_id );

// 生成自增ID的函数（线程安全）
unsigned long long generate_threadsafe_client_send_id ( ) {
    //
    unsigned long long current_id;

    //
    if ( client_send_next_id >= MAX_CLIENTS ) {
        return ERROR_CLIENT_SEND_CONNECTION_ID_CREATE;
    }

    // 加锁保护共享变量
    pthread_mutex_lock ( & client_send_id_mutex );
    current_id = client_send_next_id++;
    pthread_mutex_unlock ( & client_send_id_mutex );

    return current_id;
}

// 生成自增ID的函数（线程安全）
unsigned long long generate_threadsafe_client_receive_id ( ) {
    //
    unsigned long long current_id;

    //
    if ( client_receive_next_id >= MAX_CLIENTS ) {
        return ERROR_CLIENT_SEND_CONNECTION_ID_CREATE;
    }

    // 加锁保护共享变量
    pthread_mutex_lock ( & client_receive_id_mutex );
    current_id = client_receive_next_id++;
    pthread_mutex_unlock ( & client_receive_id_mutex );

    return current_id;
}

// 生成自增ID的函数（线程安全）
unsigned long long generate_threadsafe_server_send_id ( ) {
    //
    unsigned long long current_id;

    //
    if ( server_send_next_id >= MAX_SERVERS ) {
        return ERROR_SERVER_SEND_ID;
    }

    // 加锁保护共享变量
    pthread_mutex_lock ( & server_send_id_mutex );
    current_id = server_send_next_id++;
    pthread_mutex_unlock ( & server_send_id_mutex );

    return current_id;
}

// 生成自增ID的函数（线程安全）
unsigned long long generate_threadsafe_server_receive_id ( ) {
    //
    unsigned long long current_id;

    //
    if ( server_receive_next_id >= MAX_SERVERS ) {
        return ERROR_SERVER_RECEIVE_ID;
    }

    // 加锁保护共享变量
    pthread_mutex_lock ( & server_receive_id_mutex );
    current_id = server_receive_next_id++;
    pthread_mutex_unlock ( & server_receive_id_mutex );

    return current_id;
}

//进程级套接字配置（TCP保活机制）
int set_keepalive ( int sockfd ) {
    int keepidle  = 300;  // 300秒空闲触发
    int keepintvl = 5;   // 探测间隔5秒
    int keepcnt   = 3;     // 最大探测次数3

    if ( setsockopt ( sockfd , SOL_TCP , TCP_KEEPIDLE , & keepidle , sizeof ( keepidle ) ) < 0 ) {
        perror ( "setsockopt TCP_KEEPIDLE" );
        return -1;
    }
    setsockopt ( sockfd , SOL_TCP , TCP_KEEPINTVL , & keepintvl , sizeof ( keepintvl ) );
    setsockopt ( sockfd , SOL_TCP , TCP_KEEPCNT , & keepcnt , sizeof ( keepcnt ) );

    int optval = 1;
    setsockopt ( sockfd , SOL_SOCKET , SO_KEEPALIVE , & optval , sizeof ( optval ) );
    return 0;
}

//初始化网络连接节点
void init_socket_nodes ( ) {
    //
    memset ( client_send_nodes , 0 , ( sizeof ( struct client_send_node ) * MAX_CLIENTS ) );
    memset ( client_receive_nodes , 0 , ( sizeof ( struct client_receive_node ) * MAX_CLIENTS ) );
    //
    memset ( server_send_nodes , 0 , ( sizeof ( struct server_send_node ) * MAX_SERVERS ) );
    memset ( server_receive_nodes , 0 , ( sizeof ( struct server_receive_node ) * MAX_SERVERS ) );
    //
}

//根据数字IP地址获取字符串IP地址（返回堆空间首地址）
char * get_ip_addr_by_number ( unsigned int ip_addr_number ) {
    struct in_addr addr;
    addr.s_addr = ntohl ( htonl ( ip_addr_number ) ); // 192.168.1.1的十六进制表示
    char * ip_str = malloc ( INET_ADDRSTRLEN );
    inet_ntop ( AF_INET , & addr , ip_str , INET_ADDRSTRLEN );
    return ip_str;
}

//根据套接字标识获取数字IP地址
int get_ip_addr_number_by_socket ( int socket_fd ) {
    struct sockaddr_in addr;
    socklen_t          addr_len = sizeof ( addr );

    if ( getsockname ( socket_fd , ( struct sockaddr * ) & addr , & addr_len ) == -1 ) {
        perror ( "getsockname failed" );
        return -1;
    }
    return addr.sin_addr.s_addr;
}

//根据套接字标识获取字符串IP地址（返回堆空间首地址）
char * get_ip_addr_by_socket ( int socket_fd ) {
    struct sockaddr_in addr;
    socklen_t          addr_len = sizeof ( addr );

    if ( getsockname ( socket_fd , ( struct sockaddr * ) & addr , & addr_len ) == -1 ) {
        perror ( "getsockname failed" );
        return NULL;
    }
    char * ip_str = malloc ( INET_ADDRSTRLEN );
    inet_ntop ( AF_INET , & addr.sin_addr , ip_str , sizeof ( ip_str ) );
    return ip_str;
}

//根据套接字标识获取对应的端口号
unsigned int get_port_by_socket ( int socket_fd ) {
    struct sockaddr_in addr;
    socklen_t          addr_len = sizeof ( addr );

    if ( getsockname ( socket_fd , ( struct sockaddr * ) & addr , & addr_len ) == -1 ) {
        perror ( "getsockname failed" );
        return 0;
    }

    return ntohs ( addr.sin_port );
}

//创建客户端请求数据包
struct client_request_data * create_client_request_data (
        //
        char token[] ,
        unsigned long long internal_code ,
        unsigned long long type ,
        unsigned long long server_ip[] ,    //inet_addr ( server_ip );
        unsigned long long server_port ,
        unsigned long long request_id ,
        unsigned long long request_data_size ,
        unsigned long long request_data_offset ,
        unsigned long long current_request_data_size ,
        char * current_request_data ,
        char * current_request_data_filling
                                                        ) {
    srand ( time ( NULL ) );

    struct client_request_data * c_r_d = malloc ( sizeof ( struct client_request_data ) );
    memset ( c_r_d , 0 , sizeof ( struct client_request_data ) );
    //
    strncpy ( c_r_d->token , md5 ( token ) , MD5_STRING_SIZE );
    //
    c_r_d->internal_code             = internal_code;
    c_r_d->type                      = type;
    c_r_d->time_stamp                = ( ( unsigned int ) time ( NULL ) );
    c_r_d->rand_number               = ( ( unsigned int ) ( rand ( ) % 10000000000 ) );
    c_r_d->server_ip                 = server_ip;
    c_r_d->server_port               = server_port;
    c_r_d->request_id                = request_id;
    c_r_d->request_data_size         = request_data_size;
    c_r_d->request_data_offset       = request_data_offset;
    c_r_d->current_request_data_size = current_request_data_size;
    //
    if ( current_request_data != NULL ) {
        strncpy ( c_r_d->current_request_data , current_request_data , current_request_data_size );
    }
    if ( current_request_data_filling != NULL ) {
        strncpy ( c_r_d->current_request_data_filling , current_request_data_filling , current_request_data_size );
    }
    //
    strncpy ( c_r_d->end_flags , md5 ( "END_FLAG" ) , MD5_STRING_SIZE );

    return c_r_d;
}

//打印客户端请求数据包信息
unsigned long long print_client_request_data (
        struct client_request_data * c_r_d
                                             ) {
    if ( c_r_d != NULL ) {
        //
        size_t token_size = sizeof ( c_r_d->token ) / sizeof ( c_r_d->token[ 0 ] );
        printf ( "client request data token                        : " );
        for ( size_t token_index = 0 ;
              token_index < token_size ; token_index++ ) {
            printf ( "%c" , ( unsigned char ) c_r_d->token[ token_index ] );
        }
        printf ( "\n" );
        //
        printf ( "client request data internal_code                : %llu\n" , c_r_d->internal_code );
        printf ( "client request data type                         : %llu\n" , c_r_d->type );
        printf ( "client request data time_stamp                   : %llu\n" , c_r_d->time_stamp );
        printf ( "client request data rand_number                  : %llu\n" , c_r_d->rand_number );
        printf ( "client request data server_ip                    : %llu\n" , c_r_d->server_ip );
        printf ( "client request data server_port                  : %llu\n" , c_r_d->server_port );
        printf ( "client request data request_id                   : %llu\n" , c_r_d->request_id );
        printf ( "client request data request_data_size            : %llu\n" , c_r_d->request_data_size );
        printf ( "client request data request_data_offset          : %llu\n" , c_r_d->request_data_offset );
        printf ( "client request data current_request_data_size    : %llu\n" , c_r_d->current_request_data_size );
        //
        size_t current_request_data_size =
                       sizeof ( c_r_d->current_request_data ) / sizeof ( c_r_d->current_request_data[ 0 ] );
        printf ( "client request data current_request_data         : " );
        for ( size_t current_request_data_index = 0 ;
              current_request_data_index < current_request_data_size ; current_request_data_index++ ) {
            printf ( "\\x%02x" , ( unsigned char ) c_r_d->current_request_data[ current_request_data_index ] );
        }
        printf ( "\n" );
        //
        size_t current_request_data_filling_size = sizeof ( c_r_d->current_request_data_filling ) /
                                                   sizeof ( c_r_d->current_request_data_filling[ 0 ] );
        printf ( "client request data current_request_data_filling : " );
        for ( size_t current_request_data_filling_index = 0 ; current_request_data_filling_index <
                                                              current_request_data_filling_size ; current_request_data_filling_index++ ) {
            printf ( "\\x%02x" ,
                     ( unsigned char ) c_r_d->current_request_data_filling[ current_request_data_filling_index ] );
        }
        printf ( "\n" );
        //
        size_t end_flags_size = sizeof ( c_r_d->end_flags ) / sizeof ( c_r_d->end_flags[ 0 ] );
        printf ( "client request data end_flags                    : " );
        for ( size_t end_flags_index = 0 ;
              end_flags_index < end_flags_size ; end_flags_index++ ) {
            printf ( "%c" , ( unsigned char ) c_r_d->end_flags[ end_flags_index ] );
        }
        printf ( "\n" );
        //
        return sizeof ( struct client_request_data );
    }
    return 0;
}

//创建代理端响应数据包
struct proxy_response_data * create_proxy_response_data (
        char token[] ,
        unsigned long long internal_code ,
        unsigned long long type ,
        unsigned long long server_ip ,                    //inet_addr ( server_ip )
        unsigned long long server_port ,
        unsigned long long internal_ip ,                  //inet_addr ( internal_ip );
        unsigned long long response_id ,
        unsigned long long response_data_size ,
        unsigned long long response_data_offset ,
        unsigned long long current_response_data_size ,
        char * current_response_data ,
        char * current_response_data_filling
                                                        ) {
    srand ( time ( NULL ) );

    struct proxy_response_data * p_r_d = malloc ( sizeof ( struct proxy_response_data ) );
    memset ( p_r_d , 0 , sizeof ( struct proxy_response_data ) );
    //
    strncpy ( p_r_d->token , md5 ( token ) , MD5_STRING_SIZE );
    //
    p_r_d->internal_code              = internal_code;
    p_r_d->type                       = type;
    p_r_d->time_stamp                 = ( unsigned int ) time ( NULL );
    p_r_d->rand_number                = ( unsigned int ) ( rand ( ) % 10000000000 );
    p_r_d->server_ip                  = server_ip;
    p_r_d->server_port                = server_port;
    p_r_d->internal_ip                = internal_ip;
    p_r_d->response_id                = response_id;
    p_r_d->response_data_size         = response_data_size;
    p_r_d->response_data_offset       = response_data_offset;
    p_r_d->current_response_data_size = current_response_data_size;
    //
    if ( current_response_data != NULL ) {
        strncpy ( p_r_d->current_response_data , current_response_data , current_response_data_size );
    }
    if ( current_response_data_filling != NULL ) {
        strncpy ( p_r_d->current_response_data_filling , current_response_data_filling , current_response_data_size );
    }
    //
    strncpy ( p_r_d->end_flags , md5 ( "END_FLAG" ) , MD5_STRING_SIZE );

    return p_r_d;
}

//打印代理端响应数据包信息
unsigned long long print_proxy_response_data (
        struct proxy_response_data * p_r_d
                                             ) {
    if ( p_r_d != NULL ) {
        //
        size_t token_size = sizeof ( p_r_d->token ) / sizeof ( p_r_d->token[ 0 ] );
        printf ( "proxy response data token                         : " );
        for ( size_t token_index = 0 ;
              token_index < token_size ; token_index++ ) {
            printf ( "%c" , ( unsigned char ) p_r_d->token[ token_index ] );
        }
        printf ( "\n" );
        //
        printf ( "proxy response data internal_code                : %llu\n" , p_r_d->internal_code );
        printf ( "proxy response data type                         : %llu\n" , p_r_d->type );
        printf ( "proxy response data time_stamp                   : %llu\n" , p_r_d->time_stamp );
        printf ( "proxy response data rand_number                  : %llu\n" , p_r_d->rand_number );
        printf ( "proxy response data server_ip                    : %llu\n" , p_r_d->server_ip );
        printf ( "proxy response data server_port                  : %llu\n" , p_r_d->server_port );
        printf ( "proxy response data internal_ip                  : %llu\n" , p_r_d->internal_ip );
        printf ( "proxy response data request_id                   : %llu\n" , p_r_d->response_id );
        printf ( "proxy response data request_data_size            : %llu\n" , p_r_d->response_data_size );
        printf ( "proxy response data request_data_offset          : %llu\n" , p_r_d->response_data_offset );
        printf ( "proxy response data current_request_data_size    : %llu\n" , p_r_d->current_response_data_size );
        //
        size_t current_request_data_size =
                       sizeof ( p_r_d->current_response_data ) / sizeof ( p_r_d->current_response_data[ 0 ] );
        printf ( "proxy response data current_request_data         : " );
        for ( size_t current_request_data_index = 0 ;
              current_request_data_index < current_request_data_size ; current_request_data_index++ ) {
            printf ( "\\x%02x" , ( unsigned char ) p_r_d->current_response_data[ current_request_data_index ] );
        }
        printf ( "\n" );
        //
        size_t current_response_data_filling_size = sizeof ( p_r_d->current_response_data_filling ) /
                                                    sizeof ( p_r_d->current_response_data_filling[ 0 ] );
        printf ( "proxy response data current_request_data_filling : " );
        for ( size_t current_response_data_filling_index = 0 ; current_response_data_filling_index <
                                                               current_response_data_filling_size ; current_response_data_filling_index++ ) {
            printf ( "\\x%02x" ,
                     ( unsigned char ) p_r_d->current_response_data_filling[ current_response_data_filling_index ] );
        }
        printf ( "\n" );
        //
        size_t end_flags_size = sizeof ( p_r_d->end_flags ) / sizeof ( p_r_d->end_flags[ 0 ] );
        printf ( "proxy response data end_flags                    : " );
        for ( size_t end_flags_index = 0 ;
              end_flags_index < end_flags_size ; end_flags_index++ ) {
            printf ( "%c" , ( unsigned char ) p_r_d->end_flags[ end_flags_index ] );
        }
        printf ( "\n" );
        //
        return sizeof ( struct proxy_response_data );
    }
    return 0;
}

//创建代理端请求数据包
struct proxy_request_data * create_proxy_request_data (
        char token[] ,
        unsigned long long internal_code ,
        unsigned long long type ,
        unsigned long long channel_id ,
        unsigned long long request_id ,
        unsigned long long request_data_size ,
        unsigned long long request_data_offset ,
        unsigned long long current_request_data_size ,
        char * current_request_data ,
        char * current_request_data_filling
                                                      ) {
    srand ( time ( NULL ) );

    struct proxy_request_data * s_r_d = malloc ( sizeof ( struct proxy_request_data ) );
    memset ( s_r_d , 0 , sizeof ( struct proxy_request_data ) );
    //
    strncpy ( s_r_d->token , md5 ( token ) , MD5_STRING_SIZE );
    //
    s_r_d->internal_code             = internal_code;
    s_r_d->type                      = type;
    s_r_d->time_stamp                = ( unsigned int ) time ( NULL );
    s_r_d->rand_number               = ( unsigned int ) ( rand ( ) % 10000000000 );
    s_r_d->channel_id                = channel_id;
    s_r_d->request_id                = request_id;
    s_r_d->request_data_size         = request_data_size;
    s_r_d->request_data_offset       = request_data_offset;
    s_r_d->current_request_data_size = current_request_data_size;

    strncpy ( s_r_d->current_request_data , current_request_data , current_request_data_size );
    strncpy ( s_r_d->current_request_data_filling , current_request_data_filling , current_request_data_size );

    strncpy ( s_r_d->end_flags , md5 ( "END_FLAG" ) , MD5_STRING_SIZE );

    return s_r_d;
}

//打印代理端请求数据包信息
unsigned long long print_proxy_request_data (
        struct proxy_request_data * p_r_d
                                            ) {
    if ( p_r_d != NULL ) {
        //
        size_t token_size = sizeof ( p_r_d->token ) / sizeof ( p_r_d->token[ 0 ] );
        printf ( "proxy request data token                        : " );
        for ( size_t token_index = 0 ;
              token_index < token_size ; token_index++ ) {
            printf ( "%c" , ( unsigned char ) p_r_d->token[ token_index ] );
        }
        printf ( "\n" );
        //
        printf ( "proxy request data internal_code                : %llu\n" , p_r_d->internal_code );
        printf ( "proxy request data type                         : %llu\n" , p_r_d->type );
        printf ( "proxy request data time_stamp                   : %llu\n" , p_r_d->time_stamp );
        printf ( "proxy request data rand_number                  : %llu\n" , p_r_d->rand_number );
        printf ( "proxy request data channel_id                   : %llu\n" , p_r_d->channel_id );
        printf ( "proxy request data request_id                   : %llu\n" , p_r_d->request_id );
        printf ( "proxy request data request_data_size            : %llu\n" , p_r_d->request_data_size );
        printf ( "proxy request data request_data_offset          : %llu\n" , p_r_d->request_data_offset );
        printf ( "proxy request data current_request_data_size    : %llu\n" , p_r_d->current_request_data_size );
        //
        size_t current_response_data_size =
                       sizeof ( p_r_d->current_request_data ) / sizeof ( p_r_d->current_request_data[ 0 ] );
        printf ( "proxy request data current_response_data         : " );
        for ( size_t current_response_data_index = 0 ;
              current_response_data_index < current_response_data_size ; current_response_data_index++ ) {
            printf ( "\\x%02x" , ( unsigned char ) p_r_d->current_request_data[ current_response_data_index ] );
        }
        printf ( "\n" );
        //
        size_t current_request_data_filling_size = sizeof ( p_r_d->current_request_data_filling ) /
                                                   sizeof ( p_r_d->current_request_data_filling[ 0 ] );
        printf ( "proxy request data current_response_data_filling : " );
        for ( size_t current_request_data_filling_index = 0 ; current_request_data_filling_index <
                                                              current_request_data_filling_size ; current_request_data_filling_index++ ) {
            printf ( "\\x%02x" ,
                     ( unsigned char ) p_r_d->current_request_data_filling[ current_request_data_filling_index ] );
        }
        printf ( "\n" );
        //
        size_t end_flags_size = sizeof ( p_r_d->end_flags ) / sizeof ( p_r_d->end_flags[ 0 ] );
        printf ( "proxy request data end_flags                    : " );
        for ( size_t end_flags_index = 0 ;
              end_flags_index < end_flags_size ; end_flags_index++ ) {
            printf ( "%c" , ( unsigned char ) p_r_d->end_flags[ end_flags_index ] );
        }
        printf ( "\n" );
        //
        return sizeof ( struct proxy_request_data );
    }
    return 0;
}

//创建服务端应打包
struct server_response_data * create_server_response_data (
        char token[] ,
        unsigned long long internal_code ,
        unsigned long long type ,
        unsigned long long channel_id ,
        unsigned long long response_id ,
        unsigned long long internal_ip ,                  //inet_addr ( internal_ip );
        unsigned long long response_data_size ,
        unsigned long long response_data_offset ,
        unsigned long long current_response_data_size ,
        char * current_response_data ,
        char * current_response_data_filling ,
        char end_flags[]
                                                          ) {
    srand ( time ( NULL ) );

    struct server_response_data * s_r_d = malloc ( sizeof ( struct server_response_data ) );
    memset ( s_r_d , 0 , sizeof ( struct server_response_data ) );
    //
    strncpy ( s_r_d->token , md5 ( token ) , MD5_STRING_SIZE );
    //
    s_r_d->internal_code              = internal_code;
    s_r_d->type                       = type;
    s_r_d->time_stamp                 = ( unsigned int ) time ( NULL );
    s_r_d->rand_number                = ( unsigned int ) ( rand ( ) % 10000000000 );
    s_r_d->response_id                = response_id;
    s_r_d->channel_id                 = channel_id;
    s_r_d->internal_ip                = internal_ip;
    s_r_d->response_data_size         = response_data_size;
    s_r_d->response_data_offset       = response_data_offset;
    s_r_d->current_response_data_size = current_response_data_size;

    strncpy ( s_r_d->current_response_data , current_response_data , current_response_data_size );
    strncpy ( s_r_d->current_response_data_filling , current_response_data_filling , current_response_data_size );

    strncpy ( s_r_d->end_flags , md5 ( "END_FLAG" ) , MD5_STRING_SIZE );

    return s_r_d;
}

//打印服务端应答包信息
unsigned long long print_server_response_data (
        struct server_response_data * s_r_d
                                              ) {
    if ( s_r_d != NULL ) {
        //
        size_t token_size = sizeof ( s_r_d->token ) / sizeof ( s_r_d->token[ 0 ] );
        printf ( "server response data token                        : " );
        for ( size_t token_index = 0 ;
              token_index < token_size ; token_index++ ) {
            printf ( "%c" , ( unsigned char ) s_r_d->token[ token_index ] );
        }
        printf ( "\n" );
        //
        printf ( "server response data internal_code                : %llu\n" , s_r_d->internal_code );
        printf ( "server response data type                         : %llu\n" , s_r_d->type );
        printf ( "server response data time_stamp                   : %llu\n" , s_r_d->time_stamp );
        printf ( "server response data rand_number                  : %llu\n" , s_r_d->rand_number );
        printf ( "server response data channel_id                   : %llu\n" , s_r_d->channel_id );
        printf ( "server response data request_id                   : %llu\n" , s_r_d->response_id );
        printf ( "server response data internal_ip                  : %llu\n" , s_r_d->internal_ip );
        printf ( "server response data request_data_size            : %llu\n" , s_r_d->response_data_size );
        printf ( "server response data request_data_offset          : %llu\n" , s_r_d->response_data_offset );
        printf ( "server response data current_request_data_size    : %llu\n" , s_r_d->current_response_data_size );
        //
        size_t current_response_data_size =
                       sizeof ( s_r_d->current_response_data ) / sizeof ( s_r_d->current_response_data[ 0 ] );
        printf ( "server response data current_response_data        : " );
        for ( size_t current_response_data_index = 0 ;
              current_response_data_index < current_response_data_size ; current_response_data_index++ ) {
            printf ( "\\x%02x" , ( unsigned char ) s_r_d->current_response_data[ current_response_data_index ] );
        }
        printf ( "\n" );
        //
        size_t current_response_data_filling_size = sizeof ( s_r_d->current_response_data_filling ) /
                                                    sizeof ( s_r_d->current_response_data_filling[ 0 ] );
        printf ( "server response data current_response_data_filling : " );
        for ( size_t current_response_data_filling_index = 0 ; current_response_data_filling_index <
                                                               current_response_data_filling_size ; current_response_data_filling_index++ ) {
            printf ( "\\x%02x" ,
                     ( unsigned char ) s_r_d->current_response_data_filling[ current_response_data_filling_index ] );
        }
        printf ( "\n" );
        //
        size_t end_flags_size = sizeof ( s_r_d->end_flags ) / sizeof ( s_r_d->end_flags[ 0 ] );
        printf ( "server response data end_flags                    : " );
        for ( size_t end_flags_index = 0 ;
              end_flags_index < end_flags_size ; end_flags_index++ ) {
            printf ( "%c" , ( unsigned char ) s_r_d->end_flags[ end_flags_index ] );
        }
        printf ( "\n" );
        //
        return sizeof ( struct server_response_data );
    }
    return 0;
}

//消息广播机制（群发消息到所有服务端）
void broadcast_message_to_server ( int client_socket ,
                                   unsigned long long internal_code ,
                                   unsigned int client_send_ip ,
                                   unsigned int client_send_port ,
                                   pthread_t client_send_thread_id ,
                                   const char * client_send_data ) {
    pthread_mutex_lock ( & server_receive_nodes_mutex );
    //
    struct client_request_data * c_r_d = (struct client_request_data * ) client_send_data;
    //
    for ( unsigned int server_receive_nodes_index = 0 ;
          server_receive_nodes_index < MAX_SERVERS ; server_receive_nodes_index++ ) {
        if ( server_receive_nodes[ server_receive_nodes_index ].is_vaild != 0 ) {
            if((server_receive_nodes[ server_receive_nodes_index ].server_ip==c_r_d->server_ip)&&(server_receive_nodes[ server_receive_nodes_index ].server_port==c_r_d->server_port)&&(server_receive_nodes[ server_receive_nodes_index ].is_vaild==SERVERS_NODE_IS_TRUE)){
                struct proxy_request_data * p_r_d = create_proxy_request_data (c_r_d->token,c_r_d->internal_code,c_r_d->type,client_send_thread_id,c_r_d->request_id,c_r_d->request_data_size,c_r_d->request_data_offset,c_r_d->current_request_data_size,c_r_d->current_request_data,c_r_d->current_request_data_filling);
                send ( server_receive_nodes[ server_receive_nodes_index ].server_socket , p_r_d , sizeof(struct proxy_request_data) ,
                       MSG_NOSIGNAL );
                print_proxy_request_data (p_r_d);
                free(p_r_d);
            }
        }
    }
    pthread_mutex_unlock ( & server_receive_nodes_mutex );
}

//消息广播机制（群发消息到所有客户端）
void broadcast_message_to_client ( int server_socket ,
                                   unsigned long long internal_code ,
                                   unsigned int server_send_ip ,
                                   unsigned int server_send_port ,
                                   pthread_t server_send_thread_id ,
                                   const char * server_send_data ) {
    pthread_mutex_lock ( & client_receive_nodes_mutex );
    //
    struct server_response_data * s_r_d = (struct server_response_data * ) server_send_data;
    //
    for ( unsigned int client_receive_nodes_index = 0 ;
          client_receive_nodes_index < MAX_CLIENTS ; client_receive_nodes_index++ ) {
        if ( client_receive_nodes[ client_receive_nodes_index ].is_vaild != 0 ) {
            if((client_receive_nodes[ client_receive_nodes_index ].client_thread_id==s_r_d->channel_id)&&(client_receive_nodes[ client_receive_nodes_index ].is_vaild==CLIENTS_NODE_IS_TRUE)) {
                struct proxy_response_data * p_r_d = create_proxy_response_data (s_r_d->token,s_r_d->internal_code,s_r_d->type,server_send_ip,server_send_port,s_r_d->internal_ip,s_r_d->response_id,s_r_d->response_data_size,s_r_d->response_data_offset,s_r_d->current_response_data_size,s_r_d->current_response_data,s_r_d->current_response_data_filling);
                send ( client_receive_nodes[ client_receive_nodes_index ].client_socket , p_r_d ,
                       sizeof(struct proxy_response_data) ,
                       MSG_NOSIGNAL );
                print_proxy_response_data (p_r_d);
                free(p_r_d);
            }
        }
    }
    pthread_mutex_unlock ( & client_receive_nodes_mutex );
}

//序列化客户端请求包内容
Buffer serialize_client_request_data ( struct client_request_data * data ) {
    Buffer       result     = { NULL , 0 };
    const size_t fixed_size = sizeof ( struct client_request_data );

    result.data = ( unsigned char * ) malloc ( fixed_size );
    if ( !result.data ) return result;

    memcpy ( result.data , data , fixed_size );
    result.length = fixed_size;

    return result;
}

//反序列化客户端请求包内容
struct client_request_data * deserialize_client_request_data ( Buffer buf ) {
    if ( buf.length != sizeof ( struct client_request_data ) ) {
        return NULL;
    }

    struct client_request_data * data = ( struct client_request_data * ) malloc (
            sizeof ( struct client_request_data ) );
    if ( !data ) return NULL;

    memcpy ( data , buf.data , buf.length );
    return data;
}

//序列化代理端请求包内容
Buffer serialize_proxy_request_data ( struct proxy_request_data * data ) {
    Buffer       result     = { NULL , 0 };
    const size_t fixed_size = sizeof ( struct proxy_request_data );

    result.data = ( unsigned char * ) malloc ( fixed_size );
    if ( !result.data ) return result;

    memcpy ( result.data , data , fixed_size );
    result.length = fixed_size;

    return result;
}

//反序列化代理端请求包内容
struct proxy_request_data * deserialize_proxy_request_data ( Buffer buf ) {
    if ( buf.length != sizeof ( struct proxy_request_data ) ) {
        return NULL;
    }

    struct proxy_request_data * data = ( struct proxy_request_data * ) malloc (
            sizeof ( struct proxy_request_data ) );
    if ( !data ) return NULL;

    memcpy ( data , buf.data , buf.length );
    return data;
}

//序列化服务端应答包内容
Buffer serialize_server_response ( struct server_response_data * data ) {
    Buffer       result     = { NULL , 0 };
    const size_t fixed_size = sizeof ( struct server_response_data );

    result.data = ( unsigned char * ) malloc ( fixed_size );
    if ( !result.data ) return result;

    memcpy ( result.data , data , fixed_size );
    result.length = fixed_size;

    return result;
}

//反序列化服务端应答包内容
struct server_response_data * deserialize_server_response ( Buffer buf ) {
    if ( buf.length != sizeof ( struct server_response_data ) ) {
        return NULL;
    }

    struct server_response_data * data = ( struct server_response_data * ) malloc (
            sizeof ( struct server_response_data ) );
    if ( !data ) return NULL;

    memcpy ( data , buf.data , buf.length );
    return data;
}


//序列化代理端应答包内容
Buffer serialize_proxy_response_data ( struct proxy_response_data * data ) {
    Buffer       result     = { NULL , 0 };
    const size_t fixed_size = sizeof ( struct proxy_response_data );

    result.data = ( unsigned char * ) malloc ( fixed_size );
    if ( !result.data ) return result;

    memcpy ( result.data , data , fixed_size );
    result.length = fixed_size;

    return result;
}

//反序列化代理端应答包内容
struct proxy_response_data * deserialize_proxy_response_data ( Buffer buf ) {
    if ( buf.length != sizeof ( struct proxy_response_data ) ) {
        return NULL;
    }

    struct proxy_response_data * data = ( struct proxy_response_data * ) malloc (
            sizeof ( struct proxy_response_data ) );
    if ( !data ) return NULL;

    memcpy ( data , buf.data , buf.length );
    return data;
}


//发送加密请求数据
void
send_encrypted_request ( int sockfd , const unsigned char * ciphertext , size_t ciphertext_len , RSA * server_pubkey ) {
    //
    Buffer encrypted = hybrid_encrypt ( ciphertext , ciphertext_len , server_pubkey );
    if ( !encrypted.data ) {
        perror ( "Encryption failed" );
        return;
    }

    // 发送加密数据
    send ( sockfd , encrypted.data , ciphertext_len , 0 );
    free ( encrypted.data );
}

//发送加密应答数据
void
send_encrypted_response ( int sockfd , const unsigned char * ciphertext , size_t ciphertext_len ,
                          RSA * server_pubkey ) {
    //
    Buffer encrypted = hybrid_encrypt ( ciphertext , ciphertext_len , server_pubkey );
    if ( !encrypted.data ) {
        perror ( "Encryption failed" );
        return;
    }

    // 发送加密数据
    send ( sockfd , encrypted.data , ciphertext_len , 0 );
    free ( encrypted.data );
}

// 检测是否为 HTTP 协议
int is_http_request ( const char * buf ) {
    return strncmp ( buf , "GET" , 3 ) == 0 ||
           strncmp ( buf , "POST" , 4 ) == 0 ||
           strncmp ( buf , "HEAD" , 4 ) == 0 ||
           strncmp ( buf , "OPTI" , 4 ) == 0 ||
           strncmp ( buf , "PUT" , 3 ) == 0;
}

// 检测是否为 HTTPS 和 HTTP 之外的网络协议
int is_other_protocol ( int sockfd ) {
    char    buffer[5];
    ssize_t n = recv ( sockfd , buffer , sizeof ( buffer ) , MSG_PEEK ); // 窥探数据不消费

    if ( n >= 3 && buffer[ 0 ] == 0x16 && buffer[ 1 ] == 0x03 ) { // TLS握手特征
        return 0;
    } else if ( is_http_request ( buffer ) ) {  // 检查HTTP方法
        return 0;
    } else {
        return 1;
    }
}

// 处理来自客户端的HTTP连接
void handle_http_for_client ( int client_socket ) {

    //
    fd_set         read_fds;
    struct timeval tv;
    char           buffer[CLIENT_BUFFER_SIZE];
    int            http_header_complete = 0;

    //初始化缓冲区
    memset ( buffer , 0 , sizeof ( buffer ) );

    // 设置非阻塞
    fcntl ( client_socket , F_SETFL , O_NONBLOCK );

    while ( !http_header_complete ) {
        FD_ZERO( & read_fds );
        FD_SET( client_socket , & read_fds );

        tv.tv_sec  = 5;
        tv.tv_usec = 0;

        int ret = select ( client_socket + 1 , & read_fds , NULL , NULL , & tv );

        if ( ret == -1 ) {
            perror ( "select error" );
            break;
        } else if ( ret == 0 ) {
            printf ( "Timeout waiting for HTTP header\n" );
            break;
        }

        if ( FD_ISSET( client_socket , & read_fds ) ) {
            ssize_t len = recv ( client_socket , buffer , sizeof ( buffer ) - 1 , 0 );

            if ( len > 0 ) {
                buffer[ len ] = 0;
                printf ( "[REQUEST] client : http data  ( %s ) \n" , buffer );

                if ( strstr ( buffer , "\r\n\r\n" ) ) {
                    send ( client_socket , http_response , strlen ( http_response ) , MSG_NOSIGNAL );
                    printf ( "[HTTP] proxy_server : Response send to client\n" );
                    http_header_complete = 1;
                }
            } else if ( len == 0 ) {
                printf ( "Client disconnected\n" );
                break;
            } else if ( errno != EAGAIN && errno != EWOULDBLOCK ) {
                perror ( "receive error" );
                break;
            }
        }
    }
}

// 处理来自客户端的HTTPS连接
void handle_https_for_client ( int client_socket ) {
    //
    SSL * ssl = SSL_new ( ssl_ctx );
    SSL_set_fd ( ssl , client_socket );

    // 优先完成SSL握手判定
    int ssl_ret = SSL_accept ( ssl ); // 执行TLS握手
    if ( ssl_ret > 0 ) {
        //
        char    buffer[CLIENT_BUFFER_SIZE];
        ssize_t len = SSL_read ( ssl , buffer , sizeof ( buffer ) - 1 );
        printf ( "[REQUEST] client : https data  ( %s ) \n" , buffer );

        if ( len > 0 ) {
            buffer[ len ] = '\0';
            if ( is_http_request ( buffer ) ) {  // 复用HTTP请求检测
                SSL_write ( ssl , https_response , strlen ( https_response ) );
                printf ( "[HTTPS] proxy_server : Secure response send to client\n" );
            } else {
                const char * err_resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 21\r\n\r\nInvalid HTTPS Request";
                SSL_write ( ssl , err_resp , strlen ( err_resp ) );
            }
        } else {
            int err = SSL_get_error ( ssl , len );
            if ( err == SSL_ERROR_ZERO_RETURN ) {
                printf ( "[HTTPS] proxy_server : Connection closed by client\n" );
            } else {
                ERR_print_errors_fp ( stderr );
            }
        }
        // SSL需要更多数据（不进行处理）
    } else if ( SSL_get_error ( ssl , ssl_ret ) == SSL_ERROR_WANT_READ ) {

        //其它情况（不进行处理）
    } else {

    }
    //释放资源
    SSL_shutdown ( ssl );
    SSL_free ( ssl );
}

//验证来自客户端的其它协议连接的通信令牌合法性
int auth_in_other_protocol_for_client ( char buffer[] ) {
    //
    if ( ( ( buffer != NULL ) && ( client_header_md5_data != NULL ) ) &&
         ( memcmp ( buffer , client_header_md5_data , MD5_STRING_SIZE ) == 0 ) ) {
        return 1;
    }
    //
    return 0;
}

// 处理来自客户端的其它协议连接
ssize_t handle_other_protocol_for_client ( int client_socket ,
                                           unsigned long long internal_code ,
                                           unsigned int ip ,
                                           unsigned int port ,
                                           pthread_t thread_id ,
                                           unsigned int handle_type ) {
    //
    char buffer[CLIENT_BUFFER_SIZE];
    memset ( buffer ,
             0 , sizeof ( buffer ) );
    ssize_t len = recv ( client_socket , buffer , sizeof ( buffer ) , MSG_DONTWAIT );
    if ( len > 0 ) {
        //如果通信令牌合法
        if ( auth_in_other_protocol_for_client ( buffer ) == 1 ) {
            //
            if ( handle_type == HANDLE_TYPE_CLIENT_SEND ) {
                add_client_send_node ( client_socket , internal_code , ip , port , thread_id );
            } else if ( handle_type == HANDLE_TYPE_CLIENT_RECEIVE ) {
                add_client_receive_node ( client_socket , internal_code , ip , port , thread_id );
            } else {
                return -1;
            }
            //
            print_client_request_data ( ( struct client_request_data * ) buffer );
            //
            printf ( "[REQUEST] client : other data  ( %s ) \n" , buffer );
            send ( client_socket , other_response , strlen ( other_response ) ,
                   0 ); //发送回显到客户端
            broadcast_message_to_server ( client_socket ,
                                          internal_code ,
                                          ip ,
                                          port ,
                                          thread_id ,
                                          buffer ); //将客户端数据转发到服务端
            return
                    len;
            //
        } else {
            close(client_socket);
            printf ( "[REQUEST] client : error ( %s ) \n" , buffer );
            print_client_request_data ( ( struct client_request_data * ) buffer );
            printf ( "[REQUEST] client : error length ( %lu ) \n" ,
                     strlen ( buffer )
                   );
            return -1;
        }
    }
    //
    return 0;
}

// 根据网络协议类型进行相应客户端通信处理
int handle_connection_for_client ( int sockfd ,
                                   unsigned long long internal_code ,
                                   unsigned int ip ,
                                   unsigned int port ,
                                   pthread_t thread_id ,
                                   unsigned int handle_type ) {
    //
    char    buffer[5];
    ssize_t n = recv ( sockfd , buffer , sizeof ( buffer ) , MSG_PEEK ); // 窥探数据不消费

    if ( n >= 3 && buffer[ 0 ] == 0x16 && buffer[ 1 ] == 0x03 ) { // TLS握手特征
        handle_https_for_client ( sockfd ); //按照HTTPS协议处理
        return 1;
    } else if ( is_http_request ( buffer ) ) {  // 检查HTTP方法
        handle_http_for_client ( sockfd ); //按照HTTP协议处理
        return 2;
    } else {
        //按照其它协议处理
        if ( handle_other_protocol_for_client ( sockfd , internal_code , ip , port , thread_id , handle_type ) ==
             -1 ) { //通信验证失败（非法请求）
            return -1;
        }
        return 3; //通信验证成功（合法请求）
    }
}

// 处理来自服务端的HTTP连接
void handle_http_for_server ( int server_socket ) {

    //
    fd_set         read_fds;
    struct timeval tv;
    char           buffer[CLIENT_BUFFER_SIZE];
    int            http_header_complete = 0;

    //初始化缓冲区
    memset ( buffer , 0 , sizeof ( buffer ) );

    // 设置非阻塞
    fcntl ( server_socket , F_SETFL , O_NONBLOCK );

    while ( !http_header_complete ) {
        FD_ZERO( & read_fds );
        FD_SET( server_socket , & read_fds );

        tv.tv_sec  = 5;
        tv.tv_usec = 0;

        int ret = select ( server_socket + 1 , & read_fds , NULL , NULL , & tv );

        if ( ret == -1 ) {
            perror ( "select error" );
            break;
        } else if ( ret == 0 ) {
            printf ( "Timeout waiting for HTTP header\n" );
            break;
        }

        if ( FD_ISSET( server_socket , & read_fds ) ) {
            ssize_t len = recv ( server_socket , buffer , sizeof ( buffer ) - 1 , 0 );

            if ( len > 0 ) {
                buffer[ len ] = 0;
                printf ( "[REQUEST] server : http data  ( %s ) \n" , buffer );

                if ( strstr ( buffer , "\r\n\r\n" ) ) {
                    send ( server_socket , http_response , strlen ( http_response ) , MSG_NOSIGNAL );
                    printf ( "[HTTP] proxy_server : Response send to server\n" );
                    http_header_complete = 1;
                }
            } else if ( len == 0 ) {
                printf ( "Server disconnected\n" );
                break;
            } else if ( errno != EAGAIN && errno != EWOULDBLOCK ) {
                perror ( "receive error" );
                break;
            }
        }
    }
}

// 处理来自服务端的HTTPS连接
void handle_https_for_server ( int server_socket ) {
    //
    SSL * ssl = SSL_new ( ssl_ctx );
    SSL_set_fd ( ssl , server_socket );

    // 优先完成SSL握手判定
    int ssl_ret = SSL_accept ( ssl ); // 执行TLS握手
    if ( ssl_ret > 0 ) {
        //
        char    buffer[SERVER_BUFFER_SIZE];
        ssize_t len = SSL_read ( ssl , buffer , sizeof ( buffer ) - 1 );
        printf ( "[REQUEST] server : https data  ( %s ) \n" , buffer );

        if ( len > 0 ) {
            buffer[ len ] = '\0';
            if ( is_http_request ( buffer ) ) {  // 复用HTTP请求检测
                SSL_write ( ssl , https_response , strlen ( https_response ) );
                printf ( "[HTTPS] proxy_server : Secure response send to server\n" );
            } else {
                const char * err_resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 21\r\n\r\nInvalid HTTPS Request";
                SSL_write ( ssl , err_resp , strlen ( err_resp ) );
            }
        } else {
            int err = SSL_get_error ( ssl , len );
            if ( err == SSL_ERROR_ZERO_RETURN ) {
                printf ( "[HTTPS] proxy_server : Connection closed by server\n" );
            } else {
                ERR_print_errors_fp ( stderr );
            }
        }
        //
    } else if ( SSL_get_error ( ssl , ssl_ret ) == SSL_ERROR_WANT_READ ) {
        // SSL需要更多数据，不应混用recv()

    } else {

    }
    SSL_shutdown ( ssl );
    SSL_free ( ssl );
}

//验证来自服务端的其它协议连接的通信令牌合法性
int auth_in_other_protocol_for_server ( char buffer[] ) {
    //
    if ( ( ( buffer != NULL ) && ( client_header_md5_data != NULL ) ) &&
         ( memcmp ( buffer , server_header_md5_data , MD5_STRING_SIZE ) == 0 ) ) {
        return 1;
    }
    //
    return 0;
}

// 处理来自服务端的其他协议连接
ssize_t handle_other_protocol_for_server ( int server_socket ,
                                           unsigned long long internal_code ,
                                           unsigned int ip ,
                                           unsigned int port ,
                                           pthread_t thread_id ,
                                           unsigned int handle_type ) {
    //
    char buffer[SERVER_BUFFER_SIZE];
    memset ( buffer , 0 , sizeof ( buffer ) );
    ssize_t len = recv ( server_socket , buffer , sizeof ( buffer ) , MSG_DONTWAIT );
    if ( len > 0 ) {
        //如果通信令牌合法
        if ( auth_in_other_protocol_for_server ( buffer ) == 1 ) {
            //
            if ( handle_type == HANDLE_TYPE_SERVER_SEND ) {
                add_server_send_node ( server_socket , internal_code , ip , port , thread_id );
            } else if ( handle_type == HANDLE_TYPE_SERVER_RECEIVE ) {
                add_server_receive_node ( server_socket , internal_code , ip , port , thread_id );
            } else {
                return -1;
            }
            //
            print_server_response_data ( ( struct server_response_data * ) buffer );
            //
            printf ( "[REQUEST] server : other data  ( %s ) \n" , buffer );
            send ( server_socket , other_response , strlen ( other_response ) , 0 ); //发送回显到服务端
            broadcast_message_to_client ( server_socket ,
                                          internal_code ,
                                          ip ,
                                          port ,
                                          thread_id ,
                                          buffer ); //将服务端数据转发到客户端
            return len;
            //
        } else {
            close(server_socket);
            printf ( "[REQUEST] server : error ( %s ) \n" , buffer );
            print_server_response_data ( ( struct server_response_data * ) buffer );
            printf ( "[REQUEST] server : error length ( %lu ) \n" , strlen ( buffer ) );
            return -1;
        }
    }
    return 0;
    //
}

// 根据网络协议类型进行相应服务端通信处理
int handle_connection_for_server ( int sockfd ,
                                   unsigned long long internal_code ,
                                   unsigned int ip ,
                                   unsigned int port ,
                                   pthread_t thread_id ,
                                   unsigned int handle_type ) {
    //
    char    buffer[5];
    ssize_t n = recv ( sockfd , buffer , sizeof ( buffer ) , MSG_PEEK ); // 窥探数据不消费

    if ( n >= 3 && buffer[ 0 ] == 0x16 && buffer[ 1 ] == 0x03 ) { // TLS握手特征
        handle_https_for_server ( sockfd );
        return 1;
    } else if ( is_http_request ( buffer ) ) {  // 检查HTTP方法
        handle_http_for_server ( sockfd );
        return 2;
    } else {
        if ( handle_other_protocol_for_server ( sockfd , internal_code , ip , port , thread_id , handle_type ) == -1 ) {
            return -1;
        }
        return 3;
    }
}

//客户端指令发送通道的连接管理（添加客户端连接）
int add_client_send_node ( int client_send_socket ,
                           unsigned long long internal_code ,
                           unsigned int client_send_ip ,
                           unsigned int client_send_port ,
                           pthread_t client_send_thread_id ) {
    //并发锁
    pthread_mutex_lock ( & client_send_nodes_mutex );
    //检测资源是否可被复用
    for (
            unsigned int client_send_nodes_index = 0 ;
            client_send_nodes_index < MAX_CLIENTS ; client_send_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( client_send_ip == client_send_nodes[ client_send_nodes_index ].client_ip ) &&
             ( client_send_port == client_send_nodes[ client_send_nodes_index ].client_port ) &&
             ( client_send_nodes[ client_send_nodes_index ].is_vaild == CLIENTS_NODE_IS_TRUE ) ) {
            pthread_mutex_unlock ( & client_send_nodes_mutex );
            //不再重复添加客户端连接
            return client_send_nodes_index;
        }
        //如果客户端IP、端口已存在，连接存活状态标志未处于激活状态
        if ( ( client_send_ip == client_send_nodes[ client_send_nodes_index ].client_ip ) &&
             ( client_send_port == client_send_nodes[ client_send_nodes_index ].client_port ) &&
             ( client_send_nodes[ client_send_nodes_index ].is_vaild == CLIENTS_NODE_IS_FALSE ) ) {
            //更新客户端IP、端口对应的连接信息
            client_send_nodes[ client_send_nodes_index ].client_socket    = client_send_socket;
            client_send_nodes[ client_send_nodes_index ].internal_code    = internal_code;
            client_send_nodes[ client_send_nodes_index ].client_thread_id = client_send_thread_id;
            client_send_nodes[ client_send_nodes_index ].is_vaild         = CLIENTS_NODE_IS_TRUE;
            //
            char * client_send_ip_string = get_ip_addr_by_number ( client_send_ip );
            printf ( "[ADD] client : %s:%d\n" , client_send_ip_string , client_send_port );
            free ( client_send_ip_string );
            //
            pthread_mutex_unlock ( & client_send_nodes_mutex );
            //返回当前客户端连接对应的客户端列表索引（客户端ID）
            return client_send_nodes_index;
        }
    }
    pthread_mutex_unlock ( & client_send_nodes_mutex );
//如果当前客户端IP、端口在客户端列表中并不存在，尝试生成客户端ID
    unsigned int client_send_nodes_current_index = ( unsigned int ) generate_threadsafe_client_send_id ( );
//如果客户端ID生成数量已达到最大值
    if ( client_send_nodes_current_index == ERROR_CLIENT_SEND_CONNECTION_ID_CREATE ) {
//关闭客户端连接
        close ( client_send_socket );
        return -2;
    }
//并发锁
    pthread_mutex_lock ( & client_send_nodes_mutex );
//新增客户端的连接信息
    client_send_nodes[ client_send_nodes_current_index ].client_socket    = client_send_socket;
    client_send_nodes[ client_send_nodes_current_index ].internal_code    = internal_code;
    client_send_nodes[ client_send_nodes_current_index ].client_ip        = client_send_ip;
    client_send_nodes[ client_send_nodes_current_index ].client_port      = client_send_port;
    client_send_nodes[ client_send_nodes_current_index ].client_thread_id = client_send_thread_id;
    client_send_nodes[ client_send_nodes_current_index ].is_vaild         = CLIENTS_NODE_IS_TRUE;
//
    char * client_ip_string = get_ip_addr_by_number ( client_send_ip );
    printf ( "[ADD] client : %s:%d\n" , client_ip_string , client_send_port );
    free ( client_ip_string );
//
    pthread_mutex_unlock ( & client_send_nodes_mutex );
//返回当前客户端连接对应的客户端列表索引（客户端ID）
    return
            client_send_nodes_current_index;
}

//客户端指令发送通道的连接管理（删除客户端连接）
int remove_client_send_node ( int client_send_socket ) {
    pthread_mutex_lock ( & client_send_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int client_send_nodes_index = 0 ;
          client_send_nodes_index < MAX_CLIENTS ; client_send_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( client_send_socket == client_send_nodes[ client_send_nodes_index ].client_socket ) &&
             ( client_send_nodes[ client_send_nodes_index ].is_vaild == CLIENTS_NODE_IS_TRUE ) ) {
            char * client_send_ip = get_ip_addr_by_socket ( client_send_socket );
            unsigned int client_send_port = get_port_by_socket ( client_send_socket );
            //关闭客户端连接
            close ( client_send_socket );
            client_send_nodes[ client_send_nodes_index ].client_socket    = 0;
            client_send_nodes[ client_send_nodes_index ].internal_code    = 0;
            client_send_nodes[ client_send_nodes_index ].client_thread_id = 0;
            client_send_nodes[ client_send_nodes_index ].is_vaild         = CLIENTS_NODE_IS_FALSE;
            printf ( "[REMOVE] client : %s:%d\n" , client_send_ip , client_send_port );
            free ( client_send_ip );
            pthread_mutex_unlock ( & client_send_nodes_mutex );
            return client_send_nodes_index;
        }
    }
    pthread_mutex_unlock ( & client_send_nodes_mutex );
    return -1;
}

//客户端指令发送通道的连接管理（删除客户端连接）
int remove_client_send_node_by_ip_port ( unsigned int client_send_ip_number , unsigned int client_send_port ) {
    pthread_mutex_lock ( & client_send_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int client_send_nodes_index = 0 ;
          client_send_nodes_index < MAX_CLIENTS ; client_send_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( client_send_ip_number == client_send_nodes[ client_send_nodes_index ].client_ip ) &&
             ( client_send_port == client_send_nodes[ client_send_nodes_index ].client_port ) &&
             ( client_send_nodes[ client_send_nodes_index ].is_vaild == CLIENTS_NODE_IS_TRUE ) ) {
            char * client_send_ip = get_ip_addr_by_number ( client_send_ip_number );
            //关闭客户端连接
            close ( client_send_nodes[ client_send_nodes_index ].client_socket );
            client_send_nodes[ client_send_nodes_index ].client_socket    = 0;
            client_send_nodes[ client_send_nodes_index ].internal_code    = 0;
            client_send_nodes[ client_send_nodes_index ].client_thread_id = 0;
            client_send_nodes[ client_send_nodes_index ].is_vaild         = CLIENTS_NODE_IS_FALSE;
            printf ( "[REMOVE] client : %s:%d\n" , client_send_ip , client_send_port );
            free ( client_send_ip );
            pthread_mutex_unlock ( & client_send_nodes_mutex );
            return client_send_nodes_index;
        }
    }
    pthread_mutex_unlock ( & client_send_nodes_mutex );
    return -1;
}

//客户端指令发送通道的连接管理（检测客户端连接是否存在）
int exist_client_send_node_by_ip_port_is_vaild ( int client_send_ip , int client_send_port , int is_vaild ) {
    pthread_mutex_lock ( & client_send_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int client_send_nodes_index = 0 ;
          client_send_nodes_index < MAX_CLIENTS ; client_send_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( client_send_ip == client_send_nodes[ client_send_nodes_index ].client_ip ) &&
             ( client_send_port == client_send_nodes[ client_send_nodes_index ].client_port ) &&
             ( client_send_nodes[ client_send_nodes_index ].is_vaild == is_vaild ) ) {
            pthread_mutex_unlock ( & client_send_nodes_mutex );
            return 1;
        }
    }
    pthread_mutex_unlock ( & client_send_nodes_mutex );
    return 0;
}

//客户端指令发送通道的连接管理（检测客户端连接是否存在）
int exist_client_send_node_by_ip_port ( int client_send_ip , int client_send_port ) {
    pthread_mutex_lock ( & client_send_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int client_send_nodes_index = 0 ;
          client_send_nodes_index < MAX_CLIENTS ; client_send_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( client_send_ip == client_send_nodes[ client_send_nodes_index ].client_ip ) &&
             ( client_send_port == client_send_nodes[ client_send_nodes_index ].client_port ) ) {
            pthread_mutex_unlock ( & client_send_nodes_mutex );
            return 1;
        }
    }
    pthread_mutex_unlock ( & client_send_nodes_mutex );
    return 0;
}

//处理来自客户端指令发送通道的通信数据
void * client_send_node_handler ( void * arg ) {
    //
    struct client_send_node * c_s_n = ( struct client_send_node * ) arg;
    c_s_n->client_thread_id = pthread_self ( );
    //
    int                client_send_socket = c_s_n->client_socket;
    unsigned long long internal_code      = c_s_n->internal_code;
    unsigned int       client_send_ip     = c_s_n->client_ip;
    unsigned int       client_send_port   = c_s_n->client_port;
    pthread_t
                       client_thread_id   = c_s_n->client_thread_id;
    //
    free ( c_s_n );
    //
    while ( 1 ) {
        //
        int connection_type = handle_connection_for_client ( client_send_socket ,
                                                             internal_code ,
                                                             client_send_ip ,
                                                             client_send_port ,
                                                             client_thread_id ,
                                                             HANDLE_TYPE_CLIENT_SEND );
        if ( connection_type != 3 ) {
            break;
        }
    }
    //
    if ( is_other_protocol ( client_send_socket ) == 1 ) {
        // 清理资源
        remove_client_send_node_by_ip_port ( client_send_ip , client_send_port );
    } else {
        close ( client_send_socket );
    }

    return NULL;
}

//监听来自客户端指令发送通道的通信请求
void accept_and_register_client_send_node ( int proxy_server_listen_socket ) {
    //
    struct sockaddr_in client_addr;
    socklen_t          client_addr_len    = sizeof ( client_addr );
    int                client_send_socket = accept ( proxy_server_listen_socket , ( struct sockaddr * ) & client_addr ,
                                                     & client_addr_len );
    //心跳探测
    set_keepalive ( client_send_socket );
    //
    // 提取客户端 IP 和端口
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop ( AF_INET , & client_addr.sin_addr , client_ip , INET_ADDRSTRLEN );
    uint16_t client_port = ntohs ( client_addr.sin_port );
    printf ( "[ACCEPT] client :  %s : %d \n" , client_ip , client_port );
    //
    struct client_send_node * c_s_n = malloc ( sizeof ( struct client_send_node ) );
    c_s_n->client_socket    = client_send_socket;
    c_s_n->client_ip        = client_addr.sin_addr.s_addr;
    c_s_n->client_port      = client_port;
    c_s_n->client_thread_id = 0;
    c_s_n->is_vaild         = CLIENTS_NODE_IS_TRUE;
    //
    pthread_t
            tid;
    if ( pthread_create ( & tid , NULL , client_send_node_handler , c_s_n ) != 0 ) { // 直接传递 s_n
        perror ( "pthread_create failed" );
        close ( client_send_socket );
        free ( c_s_n );
    } else {
        pthread_detach ( tid );
    }
}

//进行客户端指令发送通道的多监听端口初始化
void create_listeners_for_client_send_node ( struct client_send_port_listener_info * client_send_port_listeners ) {
    pthread_mutex_lock ( & client_send_listeners_mutex );
    for ( int client_send_ports_index = 0 ;
          client_send_ports_index < CLIENTS_MAX_LISTEN_PORTS ; client_send_ports_index++ ) {
        int                proxy_server_listen_socket = socket ( AF_INET , SOCK_STREAM , 0 );
        struct sockaddr_in proxy_server_listen_addr   = {
                .sin_family = AF_INET ,
                .sin_port = htons ( client_send_ports[ client_send_ports_index ] ) ,
                .sin_addr.s_addr = INADDR_ANY
        };

        setsockopt ( proxy_server_listen_socket , SOL_SOCKET , SO_REUSEADDR , & ( int ) { 1 } , sizeof ( int ) );
        bind ( proxy_server_listen_socket , ( struct sockaddr * ) & proxy_server_listen_addr ,
               sizeof ( proxy_server_listen_addr ) );
        listen ( proxy_server_listen_socket , 10 );

        client_send_port_listeners[ client_send_ports_index ] = ( struct client_send_port_listener_info ) {
                proxy_server_listen_socket ,
                client_send_ports[ client_send_ports_index ] ,
                0 };
    }
    pthread_mutex_unlock ( & client_send_listeners_mutex );
}

//启用客户端指令发送通道的多路复用监听模型
void * port_listener_thread_for_client_send_node ( void * arg ) {
    struct client_send_port_listener_info * cspli = ( struct client_send_port_listener_info * ) arg;
    struct epoll_event ev , events[CLIENTS_MAX_EVENTS];

    int epollfd = epoll_create1 ( 0 );
    ev.events  = EPOLLIN;
    ev.data.fd = cspli->proxy_server_listen_socket;
    epoll_ctl ( epollfd , EPOLL_CTL_ADD , cspli->proxy_server_listen_socket , & ev );

    while ( 1 ) {
        int       nfds = epoll_wait ( epollfd , events , CLIENTS_MAX_EVENTS , -1 );
        for ( int n    = 0 ; n < nfds ; ++n ) {
            if ( events[ n ].data.fd == cspli->proxy_server_listen_socket ) {
                accept_and_register_client_send_node ( cspli->proxy_server_listen_socket );
            }
        }
    }
    close ( epollfd );
    return NULL;
}

//客户端指令执行结果接收通道的连接管理（添加客户端连接）
int add_client_receive_node ( int client_receive_socket ,
                              unsigned long long internal_code ,
                              unsigned int client_receive_ip ,
                              unsigned int client_receive_port ,
                              pthread_t client_receive_thread_id ) {
    //并发锁
    pthread_mutex_lock ( & client_receive_nodes_mutex );
    //检测资源是否可被复用
    for ( unsigned int client_receive_nodes_index = 0 ;
          client_receive_nodes_index < MAX_CLIENTS ; client_receive_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( client_receive_ip == client_receive_nodes[ client_receive_nodes_index ].client_ip ) &&
             ( client_receive_port == client_receive_nodes[ client_receive_nodes_index ].client_port ) &&
             ( client_receive_nodes[ client_receive_nodes_index ].is_vaild == CLIENTS_NODE_IS_TRUE ) ) {
            pthread_mutex_unlock ( & client_receive_nodes_mutex );
            //不再重复添加客户端连接
            return client_receive_nodes_index;
        }
        //如果客户端IP、端口已存在，连接存活状态标志未处于激活状态
        if ( ( client_receive_ip == client_receive_nodes[ client_receive_nodes_index ].client_ip ) &&
             ( client_receive_port == client_receive_nodes[ client_receive_nodes_index ].client_port ) &&
             ( client_receive_nodes[ client_receive_nodes_index ].is_vaild == CLIENTS_NODE_IS_FALSE ) ) {
            //更新客户端IP、端口对应的连接信息
            client_receive_nodes[ client_receive_nodes_index ].client_socket    = client_receive_socket;
            client_receive_nodes[ client_receive_nodes_index ].internal_code    = internal_code;
            client_receive_nodes[ client_receive_nodes_index ].client_thread_id = client_receive_thread_id;
            client_receive_nodes[ client_receive_nodes_index ].is_vaild         = CLIENTS_NODE_IS_TRUE;
            //
            char * client_receive_ip_string = get_ip_addr_by_number ( client_receive_ip );
            printf ( "[ADD] client : %s:%d\n" , client_receive_ip_string , client_receive_port );
            free ( client_receive_ip_string );
            //
            pthread_mutex_unlock ( & client_receive_nodes_mutex );
            //返回当前客户端连接对应的客户端列表索引（客户端ID）
            return client_receive_nodes_index;
        }
    }
    pthread_mutex_unlock ( & client_receive_nodes_mutex );
    //如果当前客户端IP、端口在客户端列表中并不存在，尝试生成客户端ID
    unsigned int client_receive_nodes_current_index = ( unsigned int ) generate_threadsafe_client_receive_id ( );
    //如果客户端ID生成数量已达到最大值
    if ( client_receive_nodes_current_index == ERROR_CLIENT_RECEIVE_CONNECTION_ID_CREATE ) {
        //关闭客户端连接
        close ( client_receive_socket );
        return -2;
    }
    //并发锁
    pthread_mutex_lock ( & client_receive_nodes_mutex );
    //新增客户端的连接信息
    client_receive_nodes[ client_receive_nodes_current_index ].client_socket    = client_receive_socket;
    client_receive_nodes[ client_receive_nodes_current_index ].internal_code    = internal_code;
    client_receive_nodes[ client_receive_nodes_current_index ].client_ip        = client_receive_ip;
    client_receive_nodes[ client_receive_nodes_current_index ].client_port      = client_receive_port;
    client_receive_nodes[ client_receive_nodes_current_index ].client_thread_id = client_receive_thread_id;
    client_receive_nodes[ client_receive_nodes_current_index ].is_vaild         = CLIENTS_NODE_IS_TRUE;
    //
    char * client_ip_string = get_ip_addr_by_number ( client_receive_ip );
    printf ( "[ADD] client : %s:%d\n" , client_ip_string , client_receive_port );
    free ( client_ip_string );
    //
    pthread_mutex_unlock ( & client_receive_nodes_mutex );
    //返回当前客户端连接对应的客户端列表索引（客户端ID）
    return client_receive_nodes_current_index;
}

//客户端指令执行结果接收通道的连接管理（删除客户端连接）
int remove_client_receive_node ( int client_receive_socket ) {
    pthread_mutex_lock ( & client_receive_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int client_receive_nodes_index = 0 ;
          client_receive_nodes_index < MAX_CLIENTS ; client_receive_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( client_receive_socket == client_receive_nodes[ client_receive_nodes_index ].client_socket ) &&
             ( client_receive_nodes[ client_receive_nodes_index ].is_vaild == CLIENTS_NODE_IS_TRUE ) ) {
            char * client_receive_ip = get_ip_addr_by_socket ( client_receive_socket );
            unsigned int client_receive_port = get_port_by_socket ( client_receive_socket );
            //关闭客户端连接
            close ( client_receive_socket );
            client_receive_nodes[ client_receive_nodes_index ].client_socket    = 0;
            client_receive_nodes[ client_receive_nodes_index ].internal_code    = 0;
            client_receive_nodes[ client_receive_nodes_index ].client_thread_id = 0;
            client_receive_nodes[ client_receive_nodes_index ].is_vaild         = CLIENTS_NODE_IS_FALSE;
            printf ( "[REMOVE] client : %s:%d\n" , client_receive_ip , client_receive_port );
            free ( client_receive_ip );
            pthread_mutex_unlock ( & client_receive_nodes_mutex );
            return client_receive_nodes_index;
        }
    }
    pthread_mutex_unlock ( & client_receive_nodes_mutex );
    return -1;
}

//客户端指令执行结果接收通道的连接管理（删除客户端连接）
int remove_client_receive_node_by_ip_port ( unsigned int client_receive_ip_number , unsigned int client_receive_port ) {
    pthread_mutex_lock ( & client_receive_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int client_receive_nodes_index = 0 ;
          client_receive_nodes_index < MAX_CLIENTS ; client_receive_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( client_receive_ip_number == client_receive_nodes[ client_receive_nodes_index ].client_ip ) &&
             ( client_receive_port == client_receive_nodes[ client_receive_nodes_index ].client_port ) &&
             ( client_receive_nodes[ client_receive_nodes_index ].is_vaild == CLIENTS_NODE_IS_TRUE ) ) {
            char * client_receive_ip = get_ip_addr_by_number ( client_receive_ip_number );
            //关闭客户端连接
            close ( client_receive_nodes[ client_receive_nodes_index ].client_socket );
            client_receive_nodes[ client_receive_nodes_index ].client_socket    = 0;
            client_receive_nodes[ client_receive_nodes_index ].internal_code    = 0;
            client_receive_nodes[ client_receive_nodes_index ].client_thread_id = 0;
            client_receive_nodes[ client_receive_nodes_index ].is_vaild         = CLIENTS_NODE_IS_FALSE;
            printf ( "[REMOVE] client : %s:%d\n" , client_receive_ip , client_receive_port );
            free ( client_receive_ip );
            pthread_mutex_unlock ( & client_receive_nodes_mutex );
            return client_receive_nodes_index;
        }
    }
    pthread_mutex_unlock ( & client_receive_nodes_mutex );
    return -1;
}

//客户端指令执行结果接收通道的连接管理（检测客户端连接是否存在）
int exist_client_receive_node_by_ip_port_is_vaild ( int client_receive_ip , int client_receive_port , int is_vaild ) {
    pthread_mutex_lock ( & client_receive_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int client_receive_nodes_index = 0 ;
          client_receive_nodes_index < MAX_CLIENTS ; client_receive_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( client_receive_ip == client_receive_nodes[ client_receive_nodes_index ].client_ip ) &&
             ( client_receive_port == client_receive_nodes[ client_receive_nodes_index ].client_port ) &&
             ( client_receive_nodes[ client_receive_nodes_index ].is_vaild == is_vaild ) ) {
            pthread_mutex_unlock ( & client_receive_nodes_mutex );
            return 1;
        }
    }
    pthread_mutex_unlock ( & client_receive_nodes_mutex );
    return 0;
}

//客户端指令执行结果接收通道的连接管理（检测客户端连接是否存在）
int exist_client_receive_node_by_ip_port ( int client_receive_ip , int client_receive_port ) {
    pthread_mutex_lock ( & client_receive_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int client_receive_nodes_index = 0 ;
          client_receive_nodes_index < MAX_CLIENTS ; client_receive_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( client_receive_ip == client_receive_nodes[ client_receive_nodes_index ].client_ip ) &&
             ( client_receive_port == client_receive_nodes[ client_receive_nodes_index ].client_port ) ) {
            pthread_mutex_unlock ( & client_receive_nodes_mutex );
            return 1;
        }
    }
    pthread_mutex_unlock ( & client_receive_nodes_mutex );
    return 0;
}

//处理来自客户端指令执行结果接收通道的通信数据
void * client_receive_node_handler ( void * arg ) {
    //
    struct client_receive_node * c_r_n = ( struct client_receive_node * ) arg;
    c_r_n->client_thread_id = pthread_self ( );
    //
    int                client_receive_socket = c_r_n->client_socket;
    unsigned long long internal_code         = c_r_n->internal_code;
    unsigned int       client_receive_ip     = c_r_n->client_ip;
    unsigned int       client_receive_port   = c_r_n->client_port;
    pthread_t
                       client_thread_id      = c_r_n->client_thread_id;
    //
    free ( c_r_n );
    //
    while ( 1 ) {
        //
        int connection_type = handle_connection_for_client ( client_receive_socket ,
                                                             internal_code ,
                                                             client_receive_ip ,
                                                             client_receive_port ,
                                                             client_thread_id ,
                                                             HANDLE_TYPE_CLIENT_RECEIVE );
        if ( connection_type != 3 ) {
            break;
        }
    }
    //
    if ( is_other_protocol ( client_receive_socket ) == 1 ) {
        // 清理资源
        remove_client_receive_node_by_ip_port ( client_receive_ip , client_receive_port );
    } else {
        close ( client_receive_socket );
    }

    return NULL;
}

//监听来自客户端指令执行结果接收通道的连接请求
void accept_and_register_client_receive_node ( int proxy_server_listen_socket ) {
    //
    struct sockaddr_in client_addr;
    socklen_t          client_addr_len       = sizeof ( client_addr );
    int                client_receive_socket = accept ( proxy_server_listen_socket ,
                                                        ( struct sockaddr * ) & client_addr ,
                                                        & client_addr_len );
    //心跳探测
    set_keepalive ( client_receive_socket );
    //
    // 提取客户端 IP 和端口
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop ( AF_INET , & client_addr.sin_addr , client_ip , INET_ADDRSTRLEN );
    uint16_t client_port = ntohs ( client_addr.sin_port );
    printf ( "[ACCEPT] client :  %s : %d \n" , client_ip , client_port );
    //
    struct client_receive_node * c_r_n = malloc ( sizeof ( struct client_receive_node ) );
    c_r_n->client_socket    = client_receive_socket;
    c_r_n->client_ip        = client_addr.sin_addr.s_addr;
    c_r_n->client_port      = client_port;
    c_r_n->client_thread_id = 0;
    c_r_n->is_vaild         = CLIENTS_NODE_IS_TRUE;
    //
    pthread_t
            tid;
    if ( pthread_create ( & tid , NULL , client_receive_node_handler , c_r_n ) != 0 ) { // 直接传递 s_n
        perror ( "pthread_create failed" );
        close ( client_receive_socket );
        free ( c_r_n );
    } else {
        pthread_detach ( tid );
    }
}

//进行来自客户端指令执行结果接收通道的多监听端口初始化
void
create_listeners_for_client_receive_node ( struct client_receive_port_listener_info * client_receive_port_listeners ) {
    pthread_mutex_lock ( & client_receive_listeners_mutex );
    for ( int client_receive_ports_index = 0 ;
          client_receive_ports_index < CLIENTS_MAX_LISTEN_PORTS ; client_receive_ports_index++ ) {
        int                proxy_server_listen_socket = socket ( AF_INET , SOCK_STREAM , 0 );
        struct sockaddr_in proxy_server_listen_addr   = {
                .sin_family = AF_INET ,
                .sin_port = htons ( client_receive_ports[ client_receive_ports_index ] ) ,
                .sin_addr.s_addr = INADDR_ANY
        };

        setsockopt ( proxy_server_listen_socket , SOL_SOCKET , SO_REUSEADDR , & ( int ) { 1 } , sizeof ( int ) );
        bind ( proxy_server_listen_socket , ( struct sockaddr * ) & proxy_server_listen_addr ,
               sizeof ( proxy_server_listen_addr ) );
        listen ( proxy_server_listen_socket , 10 );

        client_receive_port_listeners[ client_receive_ports_index ] = ( struct client_receive_port_listener_info ) {
                proxy_server_listen_socket ,
                client_receive_ports[ client_receive_ports_index ] ,
                0 };
    }
    pthread_mutex_unlock ( & client_receive_listeners_mutex );
}

//启用来自客户端指令执行结果接收通道的多路复用监听模型
void * port_listener_thread_for_client_receive_node ( void * arg ) {
    struct client_receive_port_listener_info * crpli = ( struct client_receive_port_listener_info * ) arg;
    struct epoll_event ev , events[CLIENTS_MAX_EVENTS];

    int epollfd = epoll_create1 ( 0 );
    ev.events  = EPOLLIN;
    ev.data.fd = crpli->proxy_server_listen_socket;
    epoll_ctl ( epollfd , EPOLL_CTL_ADD , crpli->proxy_server_listen_socket , & ev );

    while ( 1 ) {
        int       nfds = epoll_wait ( epollfd , events , CLIENTS_MAX_EVENTS , -1 );
        for ( int n    = 0 ; n < nfds ; ++n ) {
            if ( events[ n ].data.fd == crpli->proxy_server_listen_socket ) {
                accept_and_register_client_receive_node ( crpli->proxy_server_listen_socket );
            }
        }
    }
    close ( epollfd );
    return NULL;
}

//服务端指令执行结果发送通道的连接管理（添加服务端连接）
int add_server_send_node ( int server_send_socket ,
                           unsigned long long internal_code ,
                           unsigned int server_send_ip ,
                           unsigned int server_send_port ,
                           pthread_t server_send_thread_id ) {
    //并发锁
    pthread_mutex_lock ( & server_send_nodes_mutex );
    //检测资源是否可被复用
    for ( unsigned int server_send_nodes_index = 0 ;
          server_send_nodes_index < MAX_SERVERS ; server_send_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( server_send_ip == server_send_nodes[ server_send_nodes_index ].server_ip ) &&
             ( server_send_port == server_send_nodes[ server_send_nodes_index ].server_port ) &&
             ( server_send_nodes[ server_send_nodes_index ].is_vaild == SERVERS_NODE_IS_TRUE ) ) {
            pthread_mutex_unlock ( & server_send_nodes_mutex );
            //不再重复添加客户端连接
            return server_send_nodes_index;
        }
        //如果客户端IP、端口已存在，连接存活状态标志未处于激活状态
        if ( ( server_send_ip == server_send_nodes[ server_send_nodes_index ].server_ip ) &&
             ( server_send_port == server_send_nodes[ server_send_nodes_index ].server_port ) &&
             ( server_send_nodes[ server_send_nodes_index ].is_vaild == SERVERS_NODE_IS_FALSE ) ) {
            //更新客户端IP、端口对应的连接信息
            server_send_nodes[ server_send_nodes_index ].server_socket    = server_send_socket;
            server_send_nodes[ server_send_nodes_index ].internal_code    = internal_code;
            server_send_nodes[ server_send_nodes_index ].server_thread_id = server_send_thread_id;
            server_send_nodes[ server_send_nodes_index ].is_vaild         = SERVERS_NODE_IS_TRUE;
            //
            char * server_send_ip_string = get_ip_addr_by_number ( server_send_ip );
            printf ( "[ADD] server : %s:%d\n" , server_send_ip_string , server_send_port );
            free ( server_send_ip_string );
            //
            pthread_mutex_unlock ( & server_send_nodes_mutex );
            //返回当前客户端连接对应的客户端列表索引（客户端ID）
            return server_send_nodes_index;
        }
    }
    pthread_mutex_unlock ( & server_send_nodes_mutex );
    //如果当前客户端IP、端口在客户端列表中并不存在，尝试生成客户端ID
    unsigned int server_send_nodes_current_index = ( unsigned int ) generate_threadsafe_server_send_id ( );
    //如果客户端ID生成数量已达到最大值
    if ( server_send_nodes_current_index == ERROR_SERVER_SEND_ID ) {
        //关闭客户端连接
        close ( server_send_socket );
        return -2;
    }
    //并发锁
    pthread_mutex_lock ( & server_send_nodes_mutex );
    //新增客户端的连接信息
    server_send_nodes[ server_send_nodes_current_index ].server_socket    = server_send_socket;
    server_send_nodes[ server_send_nodes_current_index ].internal_code    = internal_code;
    server_send_nodes[ server_send_nodes_current_index ].server_ip        = server_send_ip;
    server_send_nodes[ server_send_nodes_current_index ].server_port      = server_send_port;
    server_send_nodes[ server_send_nodes_current_index ].server_thread_id = server_send_thread_id;
    server_send_nodes[ server_send_nodes_current_index ].is_vaild         = SERVERS_NODE_IS_TRUE;
    //
    char * server_send_ip_string = get_ip_addr_by_number ( server_send_ip );
    printf ( "[ADD] server : %s:%d\n" , server_send_ip_string , server_send_port );
    free ( server_send_ip_string );
    //
    pthread_mutex_unlock ( & server_send_nodes_mutex );
    //返回当前客户端连接对应的客户端列表索引（客户端ID）
    return server_send_nodes_current_index;
}

//服务端指令执行结果发送通道的连接管理（删除服务端连接）
int remove_server_send_node ( int server_send_socket ) {
    pthread_mutex_lock ( & server_send_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int server_send_nodes_index = 0 ;
          server_send_nodes_index < MAX_SERVERS ; server_send_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( server_send_socket == server_send_nodes[ server_send_nodes_index ].server_socket ) &&
             ( server_send_nodes[ server_send_nodes_index ].is_vaild == SERVERS_NODE_IS_TRUE ) ) {
            char * server_send_ip = get_ip_addr_by_socket ( server_send_socket );
            unsigned int server_send_port = get_port_by_socket ( server_send_socket );
            //关闭客户端连接
            close ( server_send_socket );
            server_send_nodes[ server_send_nodes_index ].server_socket    = 0;
            server_send_nodes[ server_send_nodes_index ].internal_code    = 0;
            server_send_nodes[ server_send_nodes_index ].server_thread_id = 0;
            server_send_nodes[ server_send_nodes_index ].is_vaild         = SERVERS_NODE_IS_FALSE;
            printf ( "[REMOVE] server : %s:%d\n" , server_send_ip , server_send_port );
            free ( server_send_ip );
            pthread_mutex_unlock ( & server_send_nodes_mutex );
            return server_send_nodes_index;
        }
    }
    pthread_mutex_unlock ( & server_send_nodes_mutex );
    return -1;
}

//服务端指令执行结果发送通道的连接管理（删除服务端连接）
int remove_server_send_node_by_ip_port ( unsigned int server_send_ip_number , unsigned int server_send_port ) {
    pthread_mutex_lock ( & server_send_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int server_send_nodes_index = 0 ;
          server_send_nodes_index < MAX_SERVERS ; server_send_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( server_send_ip_number == server_send_nodes[ server_send_nodes_index ].server_ip ) &&
             ( server_send_port == server_send_nodes[ server_send_nodes_index ].server_port ) &&
             ( server_send_nodes[ server_send_nodes_index ].is_vaild == SERVERS_NODE_IS_TRUE ) ) {
            char * server_send_ip = get_ip_addr_by_number ( server_send_ip_number );
            //关闭客户端连接
            close ( server_send_nodes[ server_send_nodes_index ].server_socket );
            server_send_nodes[ server_send_nodes_index ].server_socket    = 0;
            server_send_nodes[ server_send_nodes_index ].internal_code    = 0;
            server_send_nodes[ server_send_nodes_index ].server_thread_id = 0;
            server_send_nodes[ server_send_nodes_index ].is_vaild         = SERVERS_NODE_IS_FALSE;
            printf ( "[REMOVE] server : %s:%d\n" , server_send_ip , server_send_port );
            free ( server_send_ip );
            pthread_mutex_unlock ( & server_send_nodes_mutex );
            return server_send_nodes_index;
        }
    }
    pthread_mutex_unlock ( & server_send_nodes_mutex );
    return -1;
}

//服务端指令执行结果发送通道的连接管理（检测服务端连接是否存在）
int exist_server_send_node_by_ip_port_is_vaild ( int server_send_ip , int server_send_port , int is_vaild ) {
    pthread_mutex_lock ( & server_send_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int server_send_nodes_index = 0 ;
          server_send_nodes_index < MAX_SERVERS ; server_send_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( server_send_ip == server_send_nodes[ server_send_nodes_index ].server_ip ) &&
             ( server_send_port == server_send_nodes[ server_send_nodes_index ].server_port ) &&
             ( server_send_nodes[ server_send_nodes_index ].is_vaild == is_vaild ) ) {
            pthread_mutex_unlock ( & server_send_nodes_mutex );
            return 1;
        }
    }
    pthread_mutex_unlock ( & server_send_nodes_mutex );
    return 0;
}

//服务端指令执行结果发送通道的连接管理（检测服务端连接是否存在）
int exist_server_send_node_by_ip_port ( int server_send_ip , int server_send_port ) {
    pthread_mutex_lock ( & server_send_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int server_send_nodes_index = 0 ;
          server_send_nodes_index < MAX_SERVERS ; server_send_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( server_send_ip == server_send_nodes[ server_send_nodes_index ].server_ip ) &&
             ( server_send_port == server_send_nodes[ server_send_nodes_index ].server_port ) ) {
            pthread_mutex_unlock ( & server_send_nodes_mutex );
            return 1;
        }
    }
    pthread_mutex_unlock ( & server_send_nodes_mutex );
    return 0;
}


//处理来自服务端指令执行结果发送通道的通信数据
void * server_send_node_handler ( void * arg ) {
    //
    struct server_send_node * s_s_n = ( struct server_send_node * ) arg;
    s_s_n->server_thread_id = pthread_self ( );
    //
    int                server_send_socket = s_s_n->server_socket;
    unsigned long long internal_code      = s_s_n->internal_code;
    unsigned int       server_send_ip     = s_s_n->server_ip;
    unsigned int       server_send_port   = s_s_n->server_port;
    pthread_t
                       server_thread_id   = s_s_n->server_thread_id;
    //
    free ( s_s_n );
    //
    while ( 1 ) {
        //
        int connection_type = handle_connection_for_server ( server_send_socket ,
                                                             internal_code ,
                                                             server_send_ip ,
                                                             server_send_port ,
                                                             server_thread_id ,
                                                             HANDLE_TYPE_SERVER_SEND );
        if ( connection_type != 3 ) {
            break;
        }
    }
    //
    if ( is_other_protocol ( server_send_socket ) == 1 ) {
        // 清理资源
        remove_server_send_node_by_ip_port ( server_send_ip , server_send_port );
    } else {
        close ( server_send_socket );
    }

    return NULL;
}

//监听来自服务端指令执行结果发送通道的通信请求
void accept_and_register_server_send_node ( int proxy_server_listen_socket ) {
    //
    struct sockaddr_in server_addr;
    socklen_t          server_addr_len    = sizeof ( server_addr );
    int                server_send_socket = accept ( proxy_server_listen_socket , ( struct sockaddr * ) & server_addr ,
                                                     & server_addr_len );
    //心跳探测
    set_keepalive ( server_send_socket );
    //
    // 提取客户端 IP 和端口
    char server_send_ip[INET_ADDRSTRLEN];
    inet_ntop ( AF_INET , & server_addr.sin_addr , server_send_ip , INET_ADDRSTRLEN );
    uint16_t server_send_port = ntohs ( server_addr.sin_port );
    printf ( "[ACCEPT] server :  %s : %d \n" , server_send_ip , server_send_port );
    //
    struct server_send_node * s_s_n = malloc ( sizeof ( struct server_send_node ) );
    s_s_n->server_socket    = server_send_socket;
    s_s_n->internal_code    = 0;
    s_s_n->server_ip        = server_addr.sin_addr.s_addr;
    s_s_n->server_port      = server_send_port;
    s_s_n->server_thread_id = 0;
    s_s_n->is_vaild         = SERVERS_NODE_IS_TRUE;
    //启动线程
    pthread_t
            tid;
    if ( pthread_create ( & tid , NULL , server_send_node_handler , s_s_n ) != 0 ) { // 直接传递 s_n
        perror ( "pthread_create failed" );
        close ( server_send_socket );
        free ( s_s_n );
    } else {
        pthread_detach ( tid );
    }
}


//进行来自服务端指令执行结果发送通道的多监听端口初始化
void create_listeners_for_server_send_node ( struct server_send_port_listener_info * server_send_port_listeners ) {
    pthread_mutex_lock ( & server_send_listeners_mutex );
    for ( int server_send_ports_index = 0 ;
          server_send_ports_index < SERVERS_MAX_LISTEN_PORTS ; server_send_ports_index++ ) {
        int                proxy_server_listen_socket = socket ( AF_INET , SOCK_STREAM , 0 );
        struct sockaddr_in proxy_server_listen_addr   = {
                .sin_family = AF_INET ,
                .sin_port = htons ( server_send_ports[ server_send_ports_index ] ) ,
                .sin_addr.s_addr = INADDR_ANY
        };

        setsockopt ( proxy_server_listen_socket , SOL_SOCKET , SO_REUSEADDR , & ( int ) { 1 } , sizeof ( int ) );
        bind ( proxy_server_listen_socket , ( struct sockaddr * ) & proxy_server_listen_addr ,
               sizeof ( proxy_server_listen_addr ) );
        listen ( proxy_server_listen_socket , 10 );

        server_send_port_listeners[ server_send_ports_index ] = ( struct server_send_port_listener_info ) {
                proxy_server_listen_socket ,
                server_send_ports[ server_send_ports_index ] ,
                0 };
    }
    pthread_mutex_unlock ( & server_send_listeners_mutex );
}

//启用来自服务端指令执行结果发送通道的多路复用监听模型
void * port_listener_thread_for_server_send_node ( void * arg ) {
    struct server_send_port_listener_info * sspli = ( struct server_send_port_listener_info * ) arg;
    struct epoll_event ev , events[SERVERS_MAX_EVENTS];

    int epollfd = epoll_create1 ( 0 );
    ev.events  = EPOLLIN;
    ev.data.fd = sspli->proxy_server_listen_socket;
    epoll_ctl ( epollfd , EPOLL_CTL_ADD , sspli->proxy_server_listen_socket , & ev );

    while ( 1 ) {
        int       nfds = epoll_wait ( epollfd , events , SERVERS_MAX_EVENTS , -1 );
        for ( int n    = 0 ; n < nfds ; ++n ) {
            if ( events[ n ].data.fd == sspli->proxy_server_listen_socket ) {
                accept_and_register_server_send_node ( sspli->proxy_server_listen_socket );
            }
        }
    }
    close ( epollfd );
    return NULL;
}

//服务端指令接收通道的连接管理（添加服务端连接）
int add_server_receive_node ( int server_receive_socket ,
                              unsigned long long internal_code ,
                              unsigned int server_receive_ip ,
                              unsigned int server_receive_port ,
                              pthread_t server_receive_thread_id ) {
    //并发锁
    pthread_mutex_lock ( & server_receive_nodes_mutex );
    //检测资源是否可被复用
    for ( unsigned int server_receive_nodes_index = 0 ;
          server_receive_nodes_index < MAX_SERVERS ; server_receive_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( server_receive_ip == server_receive_nodes[ server_receive_nodes_index ].server_ip ) &&
             ( server_receive_port == server_receive_nodes[ server_receive_nodes_index ].server_port ) &&
             ( server_receive_nodes[ server_receive_nodes_index ].is_vaild == SERVERS_NODE_IS_TRUE ) ) {
            pthread_mutex_unlock ( & server_receive_nodes_mutex );
            //不再重复添加客户端连接
            return server_receive_nodes_index;
        }
        //如果客户端IP、端口已存在，连接存活状态标志未处于激活状态
        if ( ( server_receive_ip == server_receive_nodes[ server_receive_nodes_index ].server_ip ) &&
             ( server_receive_port == server_receive_nodes[ server_receive_nodes_index ].server_port ) &&
             ( server_receive_nodes[ server_receive_nodes_index ].is_vaild == SERVERS_NODE_IS_FALSE ) ) {
            //更新客户端IP、端口对应的连接信息
            server_receive_nodes[ server_receive_nodes_index ].server_socket    = server_receive_socket;
            server_receive_nodes[ server_receive_nodes_index ].internal_code    = internal_code;
            server_receive_nodes[ server_receive_nodes_index ].server_thread_id = server_receive_thread_id;
            server_receive_nodes[ server_receive_nodes_index ].is_vaild         = SERVERS_NODE_IS_TRUE;
            //
            char * server_receive_ip_string = get_ip_addr_by_number ( server_receive_ip );
            printf ( "[ADD] server : %s:%d\n" , server_receive_ip_string , server_receive_port );
            free ( server_receive_ip_string );
            //
            pthread_mutex_unlock ( & server_receive_nodes_mutex );
            //返回当前客户端连接对应的客户端列表索引（客户端ID）
            return server_receive_nodes_index;
        }
    }
    pthread_mutex_unlock ( & server_receive_nodes_mutex );
    //如果当前客户端IP、端口在客户端列表中并不存在，尝试生成客户端ID
    unsigned int server_receive_nodes_current_index = ( unsigned int ) generate_threadsafe_server_receive_id ( );
    //如果客户端ID生成数量已达到最大值
    if ( server_receive_nodes_current_index == ERROR_SERVER_RECEIVE_ID ) {
        //关闭客户端连接
        close ( server_receive_socket );
        return -2;
    }
    //并发锁
    pthread_mutex_lock ( & server_receive_nodes_mutex );
    //新增客户端的连接信息
    server_receive_nodes[ server_receive_nodes_current_index ].server_socket    = server_receive_socket;
    server_receive_nodes[ server_receive_nodes_current_index ].internal_code    = internal_code;
    server_receive_nodes[ server_receive_nodes_current_index ].server_ip        = server_receive_ip;
    server_receive_nodes[ server_receive_nodes_current_index ].server_port      = server_receive_port;
    server_receive_nodes[ server_receive_nodes_current_index ].server_thread_id = server_receive_thread_id;
    server_receive_nodes[ server_receive_nodes_current_index ].is_vaild         = SERVERS_NODE_IS_TRUE;
    //
    char * server_receive_ip_string = get_ip_addr_by_number ( server_receive_ip );
    printf ( "[ADD] server : %s:%d\n" , server_receive_ip_string , server_receive_port );
    free ( server_receive_ip_string );
    //
    pthread_mutex_unlock ( & server_receive_nodes_mutex );
    //返回当前客户端连接对应的客户端列表索引（客户端ID）
    return server_receive_nodes_current_index;
}

//服务端指令接收通道的连接管理（删除服务端连接）
int remove_server_receive_node ( int server_receive_socket ) {
    pthread_mutex_lock ( & server_receive_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int server_receive_nodes_index = 0 ;
          server_receive_nodes_index < MAX_SERVERS ; server_receive_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( server_receive_socket == server_receive_nodes[ server_receive_nodes_index ].server_socket ) &&
             ( server_receive_nodes[ server_receive_nodes_index ].is_vaild == SERVERS_NODE_IS_TRUE ) ) {
            char * server_receive_ip = get_ip_addr_by_socket ( server_receive_socket );
            unsigned int server_receive_port = get_port_by_socket ( server_receive_socket );
            //关闭客户端连接
            close ( server_receive_socket );
            server_receive_nodes[ server_receive_nodes_index ].server_socket    = 0;
            server_receive_nodes[ server_receive_nodes_index ].internal_code    = 0;
            server_receive_nodes[ server_receive_nodes_index ].server_thread_id = 0;
            server_receive_nodes[ server_receive_nodes_index ].is_vaild         = SERVERS_NODE_IS_FALSE;
            printf ( "[REMOVE] server : %s:%d\n" , server_receive_ip , server_receive_port );
            free ( server_receive_ip );
            pthread_mutex_unlock ( & server_receive_nodes_mutex );
            return server_receive_nodes_index;
        }
    }
    pthread_mutex_unlock ( & server_receive_nodes_mutex );
    return -1;
}

//服务端指令接收通道的连接管理（删除服务端连接）
int remove_server_receive_node_by_ip_port ( unsigned int server_receive_ip_number , unsigned int server_receive_port ) {
    pthread_mutex_lock ( & server_receive_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int server_receive_nodes_index = 0 ;
          server_receive_nodes_index < MAX_SERVERS ; server_receive_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( server_receive_ip_number == server_receive_nodes[ server_receive_nodes_index ].server_ip ) &&
             ( server_receive_port == server_receive_nodes[ server_receive_nodes_index ].server_port ) &&
             ( server_receive_nodes[ server_receive_nodes_index ].is_vaild == SERVERS_NODE_IS_TRUE ) ) {
            char * server_receive_ip = get_ip_addr_by_number ( server_receive_ip_number );
            //关闭客户端连接
            close ( server_receive_nodes[ server_receive_nodes_index ].server_socket );
            server_receive_nodes[ server_receive_nodes_index ].server_socket    = 0;
            server_receive_nodes[ server_receive_nodes_index ].internal_code    = 0;
            server_receive_nodes[ server_receive_nodes_index ].server_thread_id = 0;
            server_receive_nodes[ server_receive_nodes_index ].is_vaild         = SERVERS_NODE_IS_FALSE;
            printf ( "[REMOVE] server : %s:%d\n" , server_receive_ip , server_receive_port );
            free ( server_receive_ip );
            pthread_mutex_unlock ( & server_receive_nodes_mutex );
            return server_receive_nodes_index;
        }
    }
    pthread_mutex_unlock ( & server_receive_nodes_mutex );
    return -1;
}

//服务端指令接收通道的连接管理（检测服务端连接是否存在）
int exist_server_receive_node_by_ip_port_is_vaild ( int server_receive_ip , int server_receive_port , int is_vaild ) {
    pthread_mutex_lock ( & server_receive_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int server_receive_nodes_index = 0 ;
          server_receive_nodes_index < MAX_SERVERS ; server_receive_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( server_receive_ip == server_receive_nodes[ server_receive_nodes_index ].server_ip ) &&
             ( server_receive_port == server_receive_nodes[ server_receive_nodes_index ].server_port ) &&
             ( server_receive_nodes[ server_receive_nodes_index ].is_vaild == is_vaild ) ) {
            pthread_mutex_unlock ( & server_receive_nodes_mutex );
            return 1;
        }
    }
    pthread_mutex_unlock ( & server_receive_nodes_mutex );
    return 0;
}

//服务端指令接收通道的连接管理（检测服务端连接是否存在）
int exist_server_receive_node_by_ip_port ( int server_receive_ip , int server_receive_port ) {
    pthread_mutex_lock ( & server_receive_nodes_mutex );
    //检测资源是否存在
    for ( unsigned int server_receive_nodes_index = 0 ;
          server_receive_nodes_index < MAX_SERVERS ; server_receive_nodes_index++ ) {
        //如果客户端IP、端口已存在，连接存活状态标志已处于激活状态
        if ( ( server_receive_ip == server_receive_nodes[ server_receive_nodes_index ].server_ip ) &&
             ( server_receive_port == server_receive_nodes[ server_receive_nodes_index ].server_port ) ) {
            pthread_mutex_unlock ( & server_receive_nodes_mutex );
            return 1;
        }
    }
    pthread_mutex_unlock ( & server_receive_nodes_mutex );
    return 0;
}


//处理来自服务端指令接收通道的通信数据
void * server_receive_node_handler ( void * arg ) {
    //
    struct server_receive_node * s_r_n = ( struct server_receive_node * ) arg;
    s_r_n->server_thread_id = pthread_self ( );
    //
    int                server_receive_socket = s_r_n->server_socket;
    unsigned long long internal_code         = s_r_n->internal_code;
    unsigned int       server_receive_ip     = s_r_n->server_ip;
    unsigned int       server_receive_port   = s_r_n->server_port;
    pthread_t
                       server_thread_id      = s_r_n->server_thread_id;
    //
    free ( s_r_n );
    //
    while ( 1 ) {
        //
        int connection_type = handle_connection_for_server ( server_receive_socket ,
                                                             internal_code ,
                                                             server_receive_ip ,
                                                             server_receive_port ,
                                                             server_thread_id ,
                                                             HANDLE_TYPE_SERVER_RECEIVE );
        if ( connection_type != 3 ) {
            break;
        }
    }
    //
    if ( is_other_protocol ( server_receive_socket ) == 1 ) {
        // 清理资源
        remove_server_receive_node_by_ip_port ( server_receive_ip , server_receive_port );
    } else {
        close ( server_receive_socket );
    }

    return NULL;
}

//监听来自服务端指令接收通道的通信请求
void accept_and_register_server_receive_node ( int proxy_server_listen_socket ) {
    //
    struct sockaddr_in server_addr;
    socklen_t          server_addr_len       = sizeof ( server_addr );
    int                server_receive_socket = accept ( proxy_server_listen_socket ,
                                                        ( struct sockaddr * ) & server_addr ,
                                                        & server_addr_len );
    //心跳探测
    set_keepalive ( server_receive_socket );
    //
    // 提取客户端 IP 和端口
    char server_receive_ip[INET_ADDRSTRLEN];
    inet_ntop ( AF_INET , & server_addr.sin_addr , server_receive_ip , INET_ADDRSTRLEN );
    uint16_t server_receive_port = ntohs ( server_addr.sin_port );
    printf ( "[ACCEPT] server :  %s : %d \n" , server_receive_ip , server_receive_port );
    //
    struct server_receive_node * s_r_n = malloc ( sizeof ( struct server_receive_node ) );
    s_r_n->server_socket    = server_receive_socket;
    s_r_n->internal_code    = 0;
    s_r_n->server_ip        = server_addr.sin_addr.s_addr;
    s_r_n->server_port      = server_receive_port;
    s_r_n->server_thread_id = 0;
    s_r_n->is_vaild         = SERVERS_NODE_IS_TRUE;
    //启动线程
    pthread_t
            tid;
    if ( pthread_create ( & tid , NULL , server_receive_node_handler , s_r_n ) != 0 ) { // 直接传递 s_n
        perror ( "pthread_create failed" );
        close ( server_receive_socket );
        free ( s_r_n );
    } else {
        pthread_detach ( tid );
    }
}


//进行来自服务端指令接收通道的多监听端口初始化
void
create_listeners_for_server_receive_node ( struct server_receive_port_listener_info * server_receive_port_listeners ) {
    pthread_mutex_lock ( & server_receive_listeners_mutex );
    for ( int server_receive_ports_index = 0 ;
          server_receive_ports_index < SERVERS_MAX_LISTEN_PORTS ; server_receive_ports_index++ ) {
        int                proxy_server_listen_socket = socket ( AF_INET , SOCK_STREAM , 0 );
        struct sockaddr_in proxy_server_listen_addr   = {
                .sin_family = AF_INET ,
                .sin_port = htons ( server_receive_ports[ server_receive_ports_index ] ) ,
                .sin_addr.s_addr = INADDR_ANY
        };

        setsockopt ( proxy_server_listen_socket , SOL_SOCKET , SO_REUSEADDR , & ( int ) { 1 } , sizeof ( int ) );
        bind ( proxy_server_listen_socket , ( struct sockaddr * ) & proxy_server_listen_addr ,
               sizeof ( proxy_server_listen_addr ) );
        listen ( proxy_server_listen_socket , 10 );

        server_receive_port_listeners[ server_receive_ports_index ] = ( struct server_receive_port_listener_info ) {
                proxy_server_listen_socket ,
                server_receive_ports[ server_receive_ports_index ] ,
                0 };
    }
    pthread_mutex_unlock ( & server_receive_listeners_mutex );
}

//启用来自服务端指令接收通道的多路复用监听模型
void * port_listener_thread_for_server_receive_node ( void * arg ) {
    struct server_receive_port_listener_info * srpli = ( struct server_receive_port_listener_info * ) arg;
    struct epoll_event ev , events[SERVERS_MAX_EVENTS];

    int epollfd = epoll_create1 ( 0 );
    ev.events  = EPOLLIN;
    ev.data.fd = srpli->proxy_server_listen_socket;
    epoll_ctl ( epollfd , EPOLL_CTL_ADD , srpli->proxy_server_listen_socket , & ev );

    while ( 1 ) {
        int       nfds = epoll_wait ( epollfd , events , SERVERS_MAX_EVENTS , -1 );
        for ( int n    = 0 ; n < nfds ; ++n ) {
            if ( events[ n ].data.fd == srpli->proxy_server_listen_socket ) {
                accept_and_register_server_receive_node ( srpli->proxy_server_listen_socket );
            }
        }
    }
    close ( epollfd );
    return NULL;
}

// 初始化OpenSSL库
void init_openssl ( ) {
    SSL_load_error_strings( );
    OpenSSL_add_ssl_algorithms( );
    ssl_ctx = SSL_CTX_new ( TLS_server_method ( ) );

    // 加载证书和私钥（需替换实际路径）
    if ( SSL_CTX_use_certificate_file ( ssl_ctx , "/applications/proxy_server/server.crt" , SSL_FILETYPE_PEM ) <=
         0 ) {
        ERR_print_errors_fp ( stderr );
        exit ( EXIT_FAILURE );
    }
    if ( SSL_CTX_use_PrivateKey_file ( ssl_ctx , "/applications/proxy_server/server.key" , SSL_FILETYPE_PEM ) <=
         0 ) {
        ERR_print_errors_fp ( stderr );
        exit ( EXIT_FAILURE );
    }
}

//代理端主程序
int proxy_main ( int argc , char * argv[] ) {
    //
    init_socket_nodes ( );
    //
    // OpenSSL初始化
    init_openssl ( );
    //
    // 初始化监听器
    create_listeners_for_server_send_node ( server_send_port_listeners );        //初始化服务端指令执行结果发送通道的对应监听器
    create_listeners_for_server_receive_node ( server_receive_port_listeners );  //初始化服务端指令接收通道的对应监听器
    create_listeners_for_client_send_node ( client_send_port_listeners );        //初始化客户端指令发送通道的对应监听器
    create_listeners_for_client_receive_node ( client_receive_port_listeners );  //初始化客户端指令执行结果接收通道的对应监听器

    // 启动服务端指令执行结果发送通道的端口监听线程
    for ( int i = 0 ; i < SERVERS_MAX_LISTEN_PORTS ; i++ ) {
        pthread_t
                tid;
        pthread_create ( & tid , NULL ,
                         port_listener_thread_for_server_send_node ,
                         & server_send_port_listeners[ i ] );
        pthread_detach ( tid );
    }

    // 启动服务端指令接收通道的端口监听线程
    for ( int i = 0 ; i < SERVERS_MAX_LISTEN_PORTS ; i++ ) {
        pthread_t
                tid;
        pthread_create ( & tid , NULL ,
                         port_listener_thread_for_server_receive_node ,
                         & server_receive_port_listeners[ i ] );
        pthread_detach ( tid );
    }

    // 启动客户端指令发送通道的端口监听线程
    for ( int i = 0 ; i < CLIENTS_MAX_LISTEN_PORTS ; i++ ) {
        pthread_t
                tid;
        pthread_create ( & tid , NULL ,
                         port_listener_thread_for_client_send_node ,
                         & client_send_port_listeners[ i ] );
        pthread_detach ( tid );
    }

    // 启动客户端指令执行结果接收通道的端口监听线程
    for ( int i = 0 ; i < CLIENTS_MAX_LISTEN_PORTS ; i++ ) {
        pthread_t
                tid;
        pthread_create ( & tid , NULL ,
                         port_listener_thread_for_client_receive_node ,
                         & client_receive_port_listeners[ i ] );
        pthread_detach ( tid );
    }

    // 主线程其他逻辑（如监控、清理等）
    while ( 1 ) sleep ( 1 );
    return 0;

}
