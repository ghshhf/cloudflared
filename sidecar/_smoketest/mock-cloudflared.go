package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// A tiny stand-in for cloudflared that just prints a "connected" line on
// start-up and waits for SIGTERM/SIGINT. Used to smoke-test the sidecar's
// Start/Stop cycle without needing real Cloudflare connectivity.
func main() {
	fmt.Println("mock-cloudflared registered tunnel connection")
	fmt.Println("mock-cloudflared ready, listening for traffic")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	for {
		select {
		case s := <-ch:
			fmt.Fprintln(os.Stderr, "received", s, "; exiting")
			os.Exit(0)
		case <-tick.C:
			fmt.Println("mock-cloudflared tick")
		}
	}
}
