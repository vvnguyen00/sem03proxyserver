package main

import (
	"io"
	"log"
	"net"
	"sync"
	"github.com/vvnguyen00/is105sem03/mycrypt"
)

func main() {
	var wg sync.WaitGroup
	proxyServer, err := net.Listen("tcp", ":8000")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("bundet til %s", proxyServer.Addr().String())
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			log.Println("f  r proxyServer.Accept() kallet")
			conn, err := proxyServer.Accept()
			if err != nil {
				return
			}
			go func(client net.Conn) {
				defer client.Close()

				server, err := net.Dial("tcp", "172.17.0.4:5000")
				if err != nil {
					log.Println(err)
					return
				}
				defer server.Close()
				err = proxy(client, server)
				if err != nil && err != io.EOF {
					log.Println(err)
				}
			}(conn)
		}
	}()
	wg.Wait()
}

func proxy(client net.Conn, server net.Conn) error {
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := server.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Println(err)
				}
				return
			}
			// Dekryptere meldingen
			dekryptertMelding := mycrypt.Krypter([]rune(string(buf[:n])), mycrypt.ALF_SEM03, len(mycrypt.ALF_SEM03)-4)

			_, err = client.Write([]byte(string(dekryptertMelding)))
			if err != nil {
				if err != io.EOF {
					log.Println(err)
				}
				return
			}
		}
	}()

	// Kryptere meldingene fra klienten før du sender dem til serveren
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := client.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Println(err)
				}
				return
			}
			kryptertMelding := mycrypt.Krypter([]rune(string(buf[:n])), mycrypt.ALF_SEM03, 4)
			_, err = server.Write([]byte(string(kryptertMelding)))
			if err != nil {
				if err != io.EOF {
					log.Println(err)
				}
				return
			}
		}
	}()

	<-make(chan struct{})
	return nil
}
