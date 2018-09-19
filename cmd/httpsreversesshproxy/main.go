package main

import (
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/user"
	"strings"
	"time"
)

var listenPort = flag.Int("listen-port", 8000, "Listen port")

var token = flag.String("token", "", "Authorization Bearer token")

var cert = flag.String("cert", "", "TLS cert file")
var key = flag.String("key", "", "TLS key file")

var identity = flag.String("identity", "", "SSH private key file")
var passphrase = flag.String("passphrase", "", "SSH private key password")
var hostname = flag.String("hostname", "", "SSH hostname")
var port = flag.Int("port", 22, "SSH port")
var password = flag.String("password", "", "SSH password")
var username = flag.String("username", "", "SSH username")
var targetURL = flag.String("target-url", "", "Target URL")

func hostKeyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {
	return nil
}

func main() {

	flag.Parse()

	if *cert == "" && *key != "" {
		log.Fatal("key specified without cert")
	}
	if *cert != "" && *key == "" {
		log.Fatal("cert specified without key")
	}

	if u, err := user.Current(); *username == "" && err == nil {
		parts := strings.Split(u.Username, "\\")
		*username = parts[len(parts)-1]
	}

	rpURL, err := url.Parse(*targetURL)
	if err != nil {
		log.Fatal(err)
	}

	if *hostname == "" || *username == "" ||
		(rpURL.Scheme != "http" && rpURL.Scheme != "https") ||
		rpURL.Host == "" {
		flag.PrintDefaults()
		return
	}

	config := &ssh.ClientConfig{
		User:            *username,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: hostKeyCallback,
	}

	if *identity != "" {
		key, err := ioutil.ReadFile(*identity)
		if err != nil {
			log.Fatal("unable to read private key: ", err)
		}
		var parse func() (ssh.Signer, error)
		if *passphrase != "" {
			parse = func() (ssh.Signer, error) {
				return ssh.ParsePrivateKeyWithPassphrase(key, []byte(*passphrase))
			}
		} else {
			parse = func() (ssh.Signer, error) {
				return ssh.ParsePrivateKey(key)
			}
		}
		signer, err := parse()
		if err != nil {
			log.Fatal("unable to parse private key: ", err)
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}
	if *password != "" {
		config.Auth = append(config.Auth, ssh.Password(*password))
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", *hostname, *port), config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		Dial:                  client.Dial,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	proxy := httputil.NewSingleHostReverseProxy(rpURL)
	proxy.Transport = transport

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *token != "" && r.Header.Get("Authorization") != "Bearer "+*token {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	if *cert == "" {
		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", *listenPort), handler))
	} else {
		log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", *listenPort), *cert, *key, handler))
	}
}
