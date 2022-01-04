package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

func fatal_err(s string){
	fmt.Print(s,"\n")
	os.Exit(-1)
}

//generate ed25519 keys

func main(){
	var priv_path = flag.String("o", "", "Output path for private key")
	var pub_path = flag.String("p", "", "Output path for public key (default is to stdout)")

	flag.Parse()

	if(*priv_path == ""){
		fatal_err("No private key output path supplied (-o)")
	}

	pubkey, privkey, err := ed25519.GenerateKey(rand.Reader)

	priv_file, err := os.Create(*priv_path)
	defer priv_file.Close()

	if(err != nil){
		fatal_err(fmt.Sprintf("Error opening private key file '%v' %v", *priv_path, err))
	}

	priv_bytes, err := x509.MarshalPKCS8PrivateKey(privkey)

	if(err != nil){
		fatal_err(fmt.Sprintf("Error marshaling private key %v", err))
	}

	pem.Encode(priv_file, &pem.Block{Type: "PRIVATE KEY", Bytes: priv_bytes})

	//write the public key
	pub_bytes, err := x509.MarshalPKIXPublicKey(pubkey)

	if(err != nil){
		fatal_err(fmt.Sprintf("Error marshaling private key %v", err))
	}

	pub_pem_block := &pem.Block{Type: "PUBLIC KEY", Bytes: pub_bytes}

	
	if(*pub_path != ""){
		pub_file, err := os.Create(*pub_path)
		defer pub_file.Close()

		if(err != nil){
			fatal_err(fmt.Sprintf("Error opening public key file '%v' %v", *pub_path, err))
		}

		pem.Encode(pub_file, pub_pem_block)
	}else{
		fmt.Print(string(pem.EncodeToMemory(pub_pem_block)))
	}
}

