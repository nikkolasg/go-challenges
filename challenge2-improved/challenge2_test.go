package challenge2

import "testing"
import "fmt"
import "time"
func Test_MultiSignature(t * testing.T) {
    // options formating 
    port1 := 6789
    port2 := 6788

    // Logging stuff
    chServer1 := make(chan string)
    chServer2 := make(chan string)
    client := make(chan string)
    go LogConnections(chServer1,chServer2,client)


    /* Server parameters generation */
    params := GenerateP256([]byte("myrandomstring"))
    pub1,pr1 := GenerateKeys(params)
    pub2,pr2 := GenerateKeys(params)
    fmt.Println("[+] Keys generated")

    serverParams1 := &ServerParams{p256: params,ch: chServer1,PublicKey:pub1,PrivateKey:pr1}
    serverParams2 := &ServerParams{p256: params,ch: chServer2,PublicKey:pub2,PrivateKey:pr2}


        go RunServer(serverParams1,port1,chServer1)
        go RunServer(serverParams2,port2,chServer2)
        address :=  fmt.Sprintf("127.0.0.1:%d",port1)
        address2 := fmt.Sprintf("127.0.0.1:%d",port2)
        server1 := Server{PublicKey: pub1,Address: address}
        server2 := Server{PublicKey: pub2,Address: address2}
        time.Sleep(100 * time.Millisecond)
        RunClient(server1,server2, params,client)

}
