package main

import (
	"crypto/tls"
	"flag"
	"log"
	"strconv"
	"sync"
)

var trHost string
var numConnections string

func init() {
	flag.StringVar(&trHost, "trHost", "127.0.0.1", "TR host to open connections to")
	flag.StringVar(&numConnections, "numConnections", "100", "No. of connections to open")
}

func main() {
	flag.Parse()

	conn, err := strconv.Atoi(numConnections)
	if err != nil {
		log.Println(err)
		return
	}
	var wg sync.WaitGroup
	wg.Add(conn)
	for i := 0; i < conn; i++ {
		go func(p int) {
			defer wg.Done()
			conf := &tls.Config{
				InsecureSkipVerify: true,
			}

			conn, err := tls.Dial("tcp", trHost, conf)
			if err != nil {
				log.Println(err)
				return
			}
			defer conn.Close()
			log.Printf("connection number %d\n", p)
		}(i)
	}
	wg.Wait()
	log.Println("finished")
}
