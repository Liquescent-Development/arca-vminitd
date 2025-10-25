package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	port := flag.Int("port", 50051, "gRPC server port")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("Starting VLAN service on port %d", *port)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal, exiting...")
		os.Exit(0)
	}()

	// Start the gRPC server
	if err := StartServer(*port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
