package main

import (
    "log"
    "crypto/tls"
    "time"
    "net"
    "io"
    "runtime"
)

var key = "ooEjjewSbQisrKA7Zb7XBrrrHSSO20xs"
var serverhost = "192.168.56.101"

func main () {
    runtime.GOMAXPROCS(1)

    log.SetFlags(log.LstdFlags | log.Lshortfile)
    log.Println("version: " + runtime.Version())

    ln, err := net.Listen("tcp", ":1082")
    if err != nil {
        log.Panic(err)
    }

    go handleAcceptRequest(ln, serverhost + ":443")

    ln, err = net.Listen("tcp", ":1083")
    if err != nil {
        log.Panic(err)
    }
    defer ln.Close()

    log.Println("key:", key)
    log.Println("localip:1082 -> remoteip:8888")
    log.Println("localip:1083 -> remoteip:8889")

    for {
        client, err := ln.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        go handleClientRequest(client, serverhost + ":8443")
    }
}

func handleAcceptRequest (ln net.Listener, host string) {
    defer ln.Close()
    for {
        client, err := ln.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        go handleClientRequest(client, host)
    }
}

func handleClientRequest (client net.Conn, host string) {
    defer client.Close()

    config := &tls.Config{
        InsecureSkipVerify: true,
    }

    d := net.Dialer{Timeout: 5 * time.Second} // 如果担心遇到恶意服务，可以额外设置Deadline: time.Now().Add(40 * time.Second)
    server, err := tls.DialWithDialer(&d, "tcp", host, config)
    if err != nil {
        log.Println(err)
        return
    }
    defer server.Close()

    _, err = server.Write([]byte(key)) // 发送认证信息
    if err != nil {
        log.Println(err)
        return
    }
    var res [1]byte
    _, err = server.Read(res[:]) // 接收认证返回信息
    if err != nil {
        log.Println(err)
        return
    }
    if res[0] != 0x01 {
        log.Println("key check fail!!!")
        return
    }

    go io.Copy(server, client)
    io.Copy(client, server)
}
