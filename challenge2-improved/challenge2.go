package challenge2
import (
    "fmt"
    "os"
    "bytes"
    "crypto/rand"
    "crypto/cipher"
    "net"
    "time"
    "strconv"
    "errors"
    "github.com/dedis/crypto/abstract"
    "github.com/dedis/crypto/nist"

)

const RandomByteLength int = 20
const ListenPort int = 6789
const ListenAddress string = "127.0.0.1"

type P256Params struct {
    Suite abstract.Suite
    Rand  abstract.Cipher
}

type Client struct {
    Params P256Params
    Servers [2]Server
    Ch chan string
}
// Client side struct server
type Server struct {
    Address string
    Con net.Conn
    PublicKey abstract.Point
}


// Server side struct server
type ServerParams struct {
    p256 P256Params
    ch chan string
    PublicKey abstract.Point
    PrivateKey abstract.Secret
    RandomSecret abstract.Secret
    Commitment abstract.Point
}

// Simply checks error and exit 
func CheckErr(err error,msg string) {
    if err != nil {
        fmt.Fprintf(os.Stderr,msg + "\n" + err.Error())
        os.Exit(1)
    }
}

// Generate RandomBytes will generate a slice of
// length bytes taken from the crypto/rand library
// (/dev/urandom on Unix)
func GenerateRandomBytes(length int) []byte {
    if length < 1 {
        fmt.Fprintf(os.Stderr,"[-] GenerateRandomBytes has received a length < 1. Abort.")
        os.Exit(1)
    }
    b := make([]byte,length)
    _,err := rand.Read(b)
    CheckErr(err,"[-] Error while generating random bytes slice")
    return b
}

// Generateparams will return a curve and and its random associated 
// Use random bytes of length RandomByteLength
func GenerateP256(buf []byte) P256Params {
    // Curve generation
    suite := nist.NewAES128SHA256P256()
    rand := suite.Cipher(buf)


    return P256Params{Suite: suite,Rand: rand}
}

// Keys generation: return public key, private key 
// derived from the p256 params
func GenerateKeys(params P256Params) (abstract.Point,abstract.Secret) {
    x := params.Suite.Secret().Pick(params.Rand)
    y := params.Suite.Point().Mul(nil,x)
    return y,x
}

// LogConnections simply log any msg the server / client want to output
func LogConnections(server <- chan string,server2 <- chan string, client <- chan string) {
    for {
        select {
        case msg := <- server:
            fmt.Printf("[+] %v (SERVER) : %s\n",time.Now(),msg)
            os.Stdout.Sync()
        case msg2 := <- server2:
            fmt.Printf("[+] :%v (SERVER2) : %s\n",time.Now(),msg2)
            os.Stdout.Sync()
        case msgClient := <- client:
            fmt.Printf("[+] %v (CLIENT) : %s\n",time.Now(),msgClient)
            os.Stdout.Sync()
        }
    }
}
func FromSecretToByte(s abstract.Secret,params P256Params) []byte {
    b := bytes.Buffer{}
    abstract.Write(&b,s,params.Suite)
    return b.Bytes()
}

func FromByteToSecret(b []byte,params P256Params) abstract.Secret {
    secret := params.Suite.Secret()
    //err := secret.UnmarshalBinary(b)
    //CheckErr(err,"[-] Error while unmarshaling secret")
    abstract.Read(bytes.NewBuffer(b),secret,params.Suite)
    return secret
}
func FromPointToByte(p abstract.Point,params P256Params) []byte {
    b := bytes.Buffer{}
    abstract.Write(&b,p,params.Suite)
    //b,err := p.MarshalBinary()
    //CheckErr(err,"[-] Error while marshiling point")
    return b.Bytes()
}
func FromByteToPoint(b []byte,params P256Params)  abstract.Point {
    point := params.Suite.Point()
    //err := point.UnmarshalBinary(b)
    //CheckErr(err,"[-] Error while unmarshling a point")
    err := abstract.Read(bytes.NewBuffer(b),point,params.Suite)
    CheckErr(err,"Error in FromByteToPoint ...")

    return point
}
// Generate the commitment and random secret values 
func (params * ServerParams) GenerateCommitment() {
    // Create random secret v and public point commitment T
    params.RandomSecret = params.p256.Suite.Secret().Pick(params.p256.Rand)
    params.Commitment = params.p256.Suite.Point().Mul(nil, params.RandomSecret)
}


// HELPER function to centralize network operations stuff
// ReadfromCon will push bytes as they are coming into the connection
func ReadFromCon(con net.Conn,errMsg string,ch chan string) []byte {
    buffer := make([]byte,1024)
    n,err := con.Read(buffer)
    CheckErr(err,fmt.Sprintf("%s (%d bytes)",errMsg,n))
    return buffer[0:n]
}
// WriteToCon are pushing bytes to the connection as they are coming from the chan
func WriteToCon(con  net.Conn,buffer []byte,errMsg string,ch chan string) {
    n,err := con.Write(buffer)
    CheckErr(err,fmt.Sprintf("%s (%d bytes)",errMsg,n))
}

// SERVER PART
// Run a new server 
// listening on specific port
// It will generate its own commitment 
// Note that public/private key are already generated (for the client ot use)
func RunServer(server *ServerParams,port int,ch chan string) {
    ListenAddress := ListenAddress + ":" + strconv.Itoa(port)
    listener,err := net.Listen("tcp",ListenAddress)
    CheckErr(err,"[-] Error while binding to " + ListenAddress + "address port")
    ch <- fmt.Sprintf("Server at port %d binded & listening ...",port)
    for {
        con,err := listener.Accept()
        CheckErr(err,"[-] Error while accepting a connection ...")
        go HandleClient(con,ch,server)
    }
}

// Implemente the multi signature algorithm for the challenge 2
func HandleClient(con net.Conn,ch chan string, params * ServerParams) {
    defer con.Close()
    ch <- fmt.Sprintf("Accepted connection from %s",con.RemoteAddr().String())

    
    time.Sleep(100 * time.Millisecond)
    // First lets receive the message from the client
    msgClient := ReadFromClient(con,"Error while retrieving message from client ",ch)
    ch <- fmt.Sprintf("Received message of %d bytes from the client.",len(msgClient))

    // Must generate its own commitment
    params.GenerateCommitment()
    ch <- fmt.Sprintf("Commitment generated...")

    // Send the commitment back to the client
    //first marshal into binary form
    //pb,err := params.Commitment.MarshalBinary()
    //CheckErr(err,"[-] Error while binarization of the commitment ..") 
    //n,err = con.Write(pb)
    //CheckErr(err,"[-] Error while sending commitment to client ..")
    cb := FromPointToByte(params.Commitment,params.p256) 
    WriteToClient(con,cb,"Error while writing the commitment to the client..",ch)
    ch <- fmt.Sprintf("Sent %d bytes of commitment to client.",len(cb))

    // Receive the aggregate commitment from client
    buf :=  ReadFromClient(con,"Error while reading aggregateCommitment from client ..",ch) 
    aggregateCommitment := FromByteToPoint(buf,params.p256)
    ch <- fmt.Sprintf("Received %d bytes of aggregated commitment from client.",len(buf))

    // compute collective challenge
    challenge := hashSchnorr(params.p256.Suite,msgClient,aggregateCommitment)

    // Compute response share r = randomsecret - privatekey * aggregateChallenge
    r := params.p256.Suite.Secret()
    r = r.Mul(params.PrivateKey, challenge).Sub(params.RandomSecret, r)

    // Sends back the response share to the client
    buf = FromSecretToByte(r,params.p256)
    WriteToClient(con,buf,"Error while sending the response share to the client ..",ch)
    ch <- fmt.Sprintf("Sent back the response share to the client (%d bytes)",len(buf))
    // ACK mechanism to not close the connection before the client send something
    ch <- fmt.Sprintf("Waiting for the ACK of the client ")
    ack  := ReadFromClient(con,"Error while reading the ACK from client..",ch)
    ch <- fmt.Sprintf("ACK received : %s",string(ack))
    time.Sleep(1 * time.Second)

}

// Channel way of receiving / transmitting over network ;)
func ReadFromClient(con net.Conn,errMsg string,ch chan string) []byte {
    return ReadFromCon(con,errMsg,ch)
}

func WriteToClient(con net.Conn,buffer []byte,errMsg string,ch chan string) {
    WriteToCon(con,buffer,errMsg,ch)
}


// Client PART. Cheating as giving the private key
// in the parameters but that is easily changeable.
// Connect a client to a server 
// Gives the address and the index to where to put this connection
// in the array of connection the client handles
func (c *Client) Connect(address string,ind int) bool {
    if ind < 0 && ind > 1 {
        fmt.Fprintf(os.Stderr,"[-] Error, want to assign a out of bound connectiom to client !")
        return false
    }
    // Connection to the server
    con,err := net.Dial("tcp",address)
    CheckErr(err,"[-] Could not connect to " + address + ".Abort.")
    c.Ch <- "Connected to " + address
    c.Servers[ind].Con = con
    return true
}

// Send a buffer to a server respresented by its index
func (c *Client) Send(ind int,buffer []byte,errMsg string)  {
    if ind < 0 && ind > 1 {
        fmt.Fprintf(os.Stderr,"[-] Error, want to assign a out of bound connectiom to client !")
        os.Exit(1)

    }
    WriteToCon(c.Servers[ind].Con,buffer,errMsg,c.Ch)
}

// Receive from a server a bunch of byte
func (c *Client) Receive(ind int,errMsg string) []byte {
    if ind < 0 && ind > 1 {
        fmt.Fprintf(os.Stderr,"[-] Error, want to assign a out of bound connectiom to client !")
        os.Exit(1)

    }
    return ReadFromCon(c.Servers[ind].Con,errMsg,c.Ch)
}


// Will send to both server this bunch of bytes
func (c *Client) SendToBoth(buffer []byte,errMsg string)  {
    c.Send(0,buffer,errMsg)
    c.Send(1,buffer,errMsg)
}

func (c *Client) ReceiveFromBoth(errMsg string) (b1,b2 []byte) {
    return c.Receive(0,errMsg) , c.Receive(1,errMsg)
}

func RunClient(s1,s2 Server,params P256Params,ch chan string) {
    // Create the client
    client := &Client{Params:params,Ch: ch,Servers: [2]Server{s1,s2}}
    // Connect to the servers
    b1 := client.Connect(s1.Address,0)
    b2 := client.Connect(s2.Address,1)
    defer func() {  client.Servers[0].Con.Close(); client.Servers[1].Con.Close() }()
    if !b1 || !b2 {
        fmt.Fprintf(os.Stderr,"Could not connect to servers. Abort.")
        os.Exit(1)
    }

    // Message to send
    msg := GenerateRandomBytes(1024)
    client.SendToBoth(msg,"Error while sending original message")
    client.Ch <- "Sent message to both servers (" + strconv.Itoa(len(msg)) + " bytes)"

    // Receive the partial commitment of each 
    client.Ch <- fmt.Sprintf("Waiting for the partial commitment of both servers...")
    pcb1,pcb2 := client.ReceiveFromBoth("Error while waiting the two partial commitment ..")
    client.Ch <- fmt.Sprintf("Received partial commitment from servers (%d,%d bytes) ",len(pcb1),len(pcb2))
    pc1, pc2 := FromByteToPoint(pcb1,params), FromByteToPoint(pcb2,params)

    // Aggregate the commitment and send back to the servers
    aggregateCommitment := pc1.Add(pc1,pc2)
    acb := FromPointToByte(aggregateCommitment,params)
    client.SendToBoth(acb,"Error while sending the aggregateCommitment to both servers")
    client.Ch <- fmt.Sprintf("Sent aggregate commitment (%d bytes) to both servers",len(acb))

    //compute collective challenge
    challenge := hashSchnorr(params.Suite,msg,aggregateCommitment)

    // Receive partial response share from clients
    prb1,prb2 := client.ReceiveFromBoth("Error while receiving partial response from servers")
    pr1,pr2 := FromByteToSecret(prb1,params), FromByteToSecret(prb2,params)
    client.Ch <- "Received both partial responses of servers..."

    // VERIFY
    // compute combined secret + combined public keys
    combinedResponse := pr1.Add(pr1,pr2)
    combinedPublicKey := s1.PublicKey.Add(s1.PublicKey,s2.PublicKey)
    // Combined Signature (to check with the already coded Schnorr verify)
    signature := bytes.Buffer{}
    sig := basicSig{challenge, combinedResponse}
    abstract.Write(&signature, &sig, params.Suite)

    err := SchnorrVerify(params.Suite,msg,combinedPublicKey,signature.Bytes())
    client.Ch <- "Verifying signature ..."
    CheckErr(err,"[-] Varying failed :( ")
    client.Ch <- "Signature passed !! "
    
    // ACK
    client.SendToBoth([]byte("ACK"),"Error while sending ACK to servers.. ")
    time.Sleep(1 * time.Second)

}


/* ******************************** */
/* Copy paste of the Schnorr algorithms taken from dedis library */
/* ********************************* */

// A basic, verifiable signature
type basicSig struct {
    C abstract.Secret // challenge
    R abstract.Secret // response
}

// Returns a secret that depends on on a message and a point
func hashSchnorr(suite abstract.Suite, message []byte, p abstract.Point) abstract.Secret {
    pb, _ := p.MarshalBinary()
    c := suite.Cipher(pb)
    c.Message(nil, nil, message)
    return suite.Secret().Pick(c)
}

// This simplified implementation of Schnorr Signatures is based on
// crypto/anon/sig.go
// The ring structure is removed and
// The anonimity set is reduced to one public key = no anonimity
func SchnorrSign(suite abstract.Suite, random cipher.Stream, message []byte,
privateKey abstract.Secret) []byte {

    // Create random secret v and public point commitment T
    v := suite.Secret().Pick(random)
    T := suite.Point().Mul(nil, v)

    // Create challenge c based on message and T
    c := hashSchnorr(suite, message, T)

    // Compute response r = v - x*c
    r := suite.Secret()
    r.Mul(privateKey, c).Sub(v, r)

    // Return verifiable signature {c, r}
    // Verifier will be able to compute v = r + x*c
    // And check that hashElgamal for T and the message == c
    buf := bytes.Buffer{}
    sig := basicSig{c, r}
    abstract.Write(&buf, &sig, suite)
    return buf.Bytes()
}

func SchnorrVerify(suite abstract.Suite, message []byte, publicKey abstract.Point,
signatureBuffer []byte) error {

    // Decode the signature
    buf := bytes.NewBuffer(signatureBuffer)
    sig := basicSig{}
    if err := abstract.Read(buf, &sig, suite); err != nil {
        return err
    }
    r := sig.R
    c := sig.C

    // Compute base**(r + x*c) == T
    var P, T abstract.Point
    P = suite.Point()
    T = suite.Point()
    T.Add(T.Mul(nil, r), P.Mul(publicKey, c))

    // Verify that the hash based on the message and T
    // matches the challange c from the signature
    c = hashSchnorr(suite, message, T)
    if !c.Equal(sig.C) {
        return errors.New("invalid signature")
    }

    return nil
}



