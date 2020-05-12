package main

import (
    "io"
    "log"
    "net"
    "strconv"
    "time"
    "runtime"
)

func main() {
    runtime.GOMAXPROCS(1)

    log.SetFlags(log.LstdFlags | log.Lshortfile)
    log.Println("version: " + runtime.Version())

    ln, err := net.Listen("tcp", ":8889")
    if err != nil {
        log.Panic(err)
    }
    defer ln.Close()

    for {
        client, err := ln.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        go handleClientRequest(client)
    }
}

func handleClientRequest(client net.Conn) {
    defer client.Close()

    var b [263]byte
    _, err := client.Read(b[:])
    if err != nil {
        log.Println(err)
        return
    }

    if b[0] == 0x05 { //只处理Socks5协议
        //客户端回应：Socks服务端不需要验证方式
        _, err2 := client.Write([]byte{0x05, 0x00})
        if err2 != nil {
            log.Println(err2)
            return
        }
        n, err3 := client.Read(b[:])
        if err3 != nil {
            log.Println(err3)
            return
        }

        var host, port string
        switch b[3] {
            case 0x01: //IP V4
                if n <= 9 {
                    return
                }
                host = net.IPv4(b[4], b[5], b[6], b[7]).String()
            case 0x03: //域名
                if n <= 7 {
                    return
                }
                host = string(b[5 : n-2]) //b[4]表示域名的长度
            case 0x04: //IP V6
                if n <= 21 {
                    return
                }
                host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
            default: return
        }
        log.Println("host", b[3], host);
        port = strconv.Itoa(int(b[n-2])<<8 | int(b[n-1]))

        d := net.Dialer{Timeout: 5 * time.Second} // 如果担心遇到恶意服务，可以额外设置Deadline: time.Now().Add(40 * time.Second)
        server, err3 := d.Dial("tcp", net.JoinHostPort(host, port))
        if err3 != nil {
            log.Println(err3)
            return
        }
        defer server.Close()

        _, err4 := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) //响应客户端连接成功
        if err4 != nil {
            log.Println(err4)
            return
        }

        //进行转发
        go io.Copy(server, client)
        io.Copy(client, server)
    }
}
