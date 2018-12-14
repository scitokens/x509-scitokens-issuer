package main

// cms-scitoken-init - Go client for CMS scitoken
// Author: Valentin Kuznetsov <vkuznet@gmail.com>
// Build instruction:
//    go get github.com/vkuznet/x509proxy # get x509proxy package
//    go build cms-scitoken-init.go       # builds cms-scitoken-init executable
// Run instructions:
//    cms-scitoken-init -url <issuer URL> # use -verbose to debug HTTP request/responses

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"os/user"

	"github.com/vkuznet/x509proxy"
)

type OpenID struct {
	Issuer        string `json:"issuer"`
	JwksUri       string `json:"jwks_uri"`
	TokenEndpoint string `json:"token_endpoint"`
}

func main() {
	var rurl string
	flag.StringVar(&rurl, "url", "", "Issuer url")
	var verbose bool
	flag.BoolVar(&verbose, "verbose", false, "verbose output")
	flag.Parse()
	token := FetchToken(rurl, verbose)
	fmt.Println(token)
}

// client X509 certificates
func tlsCerts(verbose bool) ([]tls.Certificate, error) {
	uproxy := os.Getenv("X509_USER_PROXY")
	uckey := os.Getenv("X509_USER_KEY")
	ucert := os.Getenv("X509_USER_CERT")

	// check if /tmp/x509up_u$UID exists, if so setup X509_USER_PROXY env
	u, err := user.Current()
	if err == nil {
		fname := fmt.Sprintf("/tmp/x509up_u%s", u.Uid)
		if _, err := os.Stat(fname); err == nil {
			uproxy = fname
		}
	}

	if uproxy == "" && uckey == "" { // user doesn't have neither proxy or user certs
		return nil, nil
	}
	if uproxy != "" {
		// use local implementation of LoadX409KeyPair instead of tls one
		x509cert, err := x509proxy.LoadX509Proxy(uproxy)
		if err != nil {
			return nil, fmt.Errorf("failed to parse X509 proxy: %v", err)
		}
		certs := []tls.Certificate{x509cert}
		return certs, nil
	}
	x509cert, err := tls.LoadX509KeyPair(ucert, uckey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user X509 certificate: %v", err)
	}
	certs := []tls.Certificate{x509cert}
	return certs, nil
}

// HttpClient is HTTP client for urlfetch server
func HttpClient(verbose bool) *http.Client {
	// get X509 certs
	certs, err := tlsCerts(verbose)
	if err != nil {
		panic(err.Error())
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{Certificates: certs,
			InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

// run go-routine to periodically obtain rucio token
// FetchToken request new Rucio token
func FetchToken(rurl string, verbose bool) string {
	rurl = fmt.Sprintf("%s/.well-known/openid-configuration", rurl)
	fmt.Println("Querying", rurl)
	req, _ := http.NewRequest("GET", rurl, nil)
	if verbose {
		dump, err := httputil.DumpRequestOut(req, true)
		fmt.Println(fmt.Sprintf("### HTTP header  :\n%s\n###\n", req.Header))
		fmt.Println(fmt.Sprintf("--- HTTP request :\n%s\n---\n", string(dump)))
		if err != nil {
			fmt.Println("HTTP Error", err)
		}
	}
	client := HttpClient(verbose)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("ERROR: unable to initialize HTTP client", err)
		return ""
	}
	if verbose {
		dump, err := httputil.DumpResponse(resp, true)
		fmt.Println(fmt.Sprintf("+++ HTTP response:\n%s\n+++\n", string(dump)))
		if err != nil {
			fmt.Println("HTTP Error", err)
		}
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("ERROR: unable to read response", err)
		return ""
	}
	var rec OpenID
	err = json.Unmarshal(data, &rec)
	if err != nil {
		fmt.Println("ERROR: unable to unmarshal response", err)
		return ""
	}

	// send POST request to token endpoint
	s := []byte("grant_type=client_credentials")
	req2, _ := http.NewRequest("POST", rec.TokenEndpoint, bytes.NewBuffer(s))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("Accept", "application/json")
	if verbose {
		dump, err := httputil.DumpRequestOut(req2, true)
		fmt.Println(fmt.Sprintf("### HTTP header  :\n%s\n###\n", req2.Header))
		fmt.Println(fmt.Sprintf("--- HTTP request :\n%s\n---\n", string(dump)))
		if err != nil {
			fmt.Println("HTTP Error", err)
		}
	}
	resp, err = client.Do(req2)
	if err != nil {
		fmt.Println("ERROR: unable to initialize HTTP client", err)
		return ""
	}
	if verbose {
		dump, err := httputil.DumpResponse(resp, true)
		fmt.Println(fmt.Sprintf("+++ HTTP response:\n%s\n+++\n", string(dump)))
		if err != nil {
			fmt.Println("HTTP error", err)
		}
	}
	defer resp.Body.Close()
	data, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("ERROR: unable to read response", err)
		return ""
	}
	return fmt.Sprintf(string(data))
}
