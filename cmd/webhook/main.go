package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/badboy0170/k8s-sec-hardener/internal/webhook"
)

func main() {
	var (
		port        = flag.String("port", "8443", "HTTPS port to listen on")
		certFile    = flag.String("tls-cert", "/etc/webhook/certs/tls.crt", "Path to TLS certificate")
		keyFile     = flag.String("tls-key", "/etc/webhook/certs/tls.key", "Path to TLS private key")
		clusterName = flag.String("cluster-name", "default", "Cluster name included in rejection messages")
	)
	flag.Parse()

	// Validate cert files exist
	for _, f := range []string{*certFile, *keyFile} {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			log.Fatalf("[webhook] TLS file not found: %s — run scripts/gen-certs.sh first", f)
		}
	}

	validator := webhook.NewValidator(*clusterName)

	mux := http.NewServeMux()
	mux.Handle("/validate", validator)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	addr := ":" + *port
	log.Printf("[webhook] k8s-security-hardener admission controller starting on %s", addr)
	log.Printf("[webhook] TLS cert: %s | key: %s", *certFile, *keyFile)

	if err := http.ListenAndServeTLS(addr, *certFile, *keyFile, mux); err != nil {
		log.Fatalf("[webhook] Server error: %v", err)
	}
}
