package main

import "log"
import "os"

import "github.com/gliderlabs/ssh"
import "github.com/google/gopacket"
import "github.com/google/gopacket/pcapgo"
import "github.com/google/gopacket/pcap"
import "github.com/cskr/pubsub"

type PMux struct {
	ps     *pubsub.PubSub
	handle *pcap.Handle
}

type Packet struct {
	ci   gopacket.CaptureInfo
	data []byte
}

var pmux *PMux

func main() {

	deviceName := os.Args[1]

	inactive, err := pcap.NewInactiveHandle(deviceName)
	if err != nil {
		log.Fatal(err)
	}
	defer inactive.CleanUp()

	if err = inactive.SetTimeout(pcap.BlockForever); err != nil {
		log.Fatal(err)
	} else if err = inactive.SetPromisc(true); err != nil {
		log.Fatal(err)
	} else if err = inactive.SetSnapLen(262144); err != nil {
		log.Fatal(err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	handle.SetBPFFilter("not tcp port 2222 and not tcp port 22")

	pmux = &PMux{pubsub.New(5), handle}
	go pmux.publish()
	// go localCapture()

	s := &ssh.Server{
		Addr:             ":2222",
		Handler:          sessionHandler,
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool { return true },
		PtyCallback:      func(ctx ssh.Context, pty ssh.Pty) bool { return false },
		PasswordHandler:  func(ctx ssh.Context, pass string) bool { return true },
	}

	ssh.HostKeyFile("/etc/ssh/ssh_host_rsa_key")(s)

	log.Fatal(s.ListenAndServe())
}

// Copy packets from the capture buffer to the pubsub
func (pmux *PMux) publish() {
	for {
		data, ci, err := pmux.handle.ReadPacketData()
		if err != nil {
			pmux.ps.Shutdown()
			log.Fatal(err)
			break
		}
		packet := &Packet{ci, data}
		pmux.ps.Pub(packet, "packets")
		log.Println("published a packet", packet.ci.Length)
	}
}

func sessionHandler(s ssh.Session) {
	writer := pcapgo.NewWriter(s)
	writer.WriteFileHeader(uint32(pmux.handle.SnapLen()), pmux.handle.LinkType())
	sub := pmux.ps.Sub("packets")

	// RingBuffer the subscription
	output := make(chan interface{}, 5)
	rb := NewRingBuffer(sub, output)
	go rb.Run()

	// Write packets out over the SSH session
	for packet := range output {
		log.Println("writing a packet:", packet.(*Packet).ci.CaptureLength, len(packet.(*Packet).data))
		err := writer.WritePacket(packet.(*Packet).ci, packet.(*Packet).data)
		if err != nil {
			log.Println(err)
			pmux.ps.Unsub(sub, "packets")
			s.Exit(0)
		}
	}
}

func localCapture() {
	f, _ := os.Create("/tmp/file.pcap")
	writer := pcapgo.NewWriter(f)
	writer.WriteFileHeader(uint32(pmux.handle.SnapLen()), pmux.handle.LinkType())
	sub := pmux.ps.Sub("packets")

	// RingBuffer the subscription
	output := make(chan interface{}, 5)
	rb := NewRingBuffer(sub, output)
	go rb.Run()

	// Write packets out over the SSH session
	for packet := range output {
		log.Println("writing a packet:", packet.(*Packet).ci.CaptureLength, len(packet.(*Packet).data))
		writer.WritePacket(packet.(*Packet).ci, packet.(*Packet).data)
	}

	f.Close()
}

func passwordHandler(ctx ssh.Context, pass string) bool {
	return true
}

func publicKeyHandler(ctx ssh.Context, key ssh.PublicKey) bool {
	return true
}

type RingBuffer struct {
	inputChannel  <-chan interface{}
	outputChannel chan interface{}
}

func NewRingBuffer(inputChannel <-chan interface{}, outputChannel chan interface{}) *RingBuffer {
	return &RingBuffer{inputChannel, outputChannel}
}

func (r *RingBuffer) Run() {
	for v := range r.inputChannel {
		select {
		case r.outputChannel <- v:
		default:
			log.Println("dropping a packet")
			<-r.outputChannel
			r.outputChannel <- v
		}
	}
	close(r.outputChannel)
}
