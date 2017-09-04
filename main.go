package main

import (
	"encoding/base32"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"time"

	"github.com/dgryski/dgoogauth"
)

func main() {
	var secret string
	flag.StringVar(&secret, "s", "", "google authenticator secret key")
	flag.Parse()

	if len(secret) == 0 {
		flag.PrintDefaults()
		return
	}

	var lastCode int
	var lastUpdateTimes int64
	secretBase32 := base32.StdEncoding.EncodeToString([]byte(secret))
	fmt.Println("Start calculating ...")

	//	listen for SIG
	sigCh := make(chan os.Signal)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case sig := <-sigCh:
			{
				fmt.Println("\nQuit with signal", sig.String())
				return
			}
		case <-time.After(time.Second):
			{
				tn := time.Now()
				updateTimes := tn.Unix() / int64(30)
				nextUpdateSecs := 30 - (tn.Unix() - tn.Unix()/30*30)

				// Need update
				if updateTimes != lastUpdateTimes {
					lastUpdateTimes = updateTimes
					lastCode = dgoogauth.ComputeCode(secretBase32, updateTimes)
				}
				fmt.Printf("\r [%06d] refresh after %02d second(s)", lastCode, nextUpdateSecs)
			}
		}
	}
}
