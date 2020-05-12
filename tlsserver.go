package main

import (
    "log"
    "crypto/tls"
    "time"
    "net"
    "io"
    "runtime"
    "io/ioutil"
    "encoding/json"
)

var clientlist []map[string]string
var clientnum int

func main() {
    runtime.GOMAXPROCS(1)

    log.SetFlags(log.LstdFlags | log.Lshortfile)
    log.Println("version: " + runtime.Version())

    f, err := ioutil.ReadFile("clientlist.json")
    if err != nil {
        log.Println(err)
        return
    }

    err = json.Unmarshal(f, &clientlist)
    if err != nil {
        log.Println(err)
        return
    }
    clientnum = len(clientlist)

    cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        log.Println(err)
        return
    }

    config := &tls.Config{Certificates: []tls.Certificate{cert}}
    ln, err := tls.Listen("tcp", ":443", config)
    if err != nil {
        log.Println(err)
        return
    }
    go handleAcceptRequest(ln, "127.0.0.1:8888")

    ln, err = tls.Listen("tcp", ":8443", config)
    if err != nil {
        log.Println(err)
        return
    }

    defer ln.Close()
    for {
        client, err := ln.Accept()
        if err != nil {
            log.Println(err)
            continue
        }
        go handleClientRequest(client, "127.0.0.1:8889")
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

    var key [32]byte
    _, err := client.Read(key[:])
    if err != nil {
        log.Println(err)
        return
    }
    check := false
    for i := 0 ; i < clientnum ; i++ {
        if clientlist[i]["key"] == string(key[:32]) {
            check = true
            break
        }
    }
    if check == false {
        log.Println("key check fail!!!")
        return
    }

    d := net.Dialer{Timeout: 5 * time.Second} // 如果担心遇到恶意服务，可以额外设置Deadline: time.Now().Add(40 * time.Second)
    server, err := d.Dial("tcp", host)
    if err != nil {
        log.Println(err)
        return
    }
    defer server.Close()

    _, err = client.Write([]byte{0x01}) //响应客户端连接成功
    if err != nil {
        log.Println(err)
        return
    }

    go io.Copy(server, client)
    io.Copy(client, server)
}
