package seal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func read_pem(file string) (*pem.Block, error){
    contents, err := ioutil.ReadFile(file)

	if(err != nil){
		return nil, err
	}

	block, _ := pem.Decode(contents)

	if(block==nil){
		return nil, fmt.Errorf("No PEM found")
	}

	return block, nil
}

func ReadPrivateKey(file string) (crypto.Signer, error) {
	block, err := read_pem(file)

	if(err != nil){
		return nil, err
	}

    if(block.Type == "PRIVATE KEY"){
    	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)

    	if(err != nil){
    		return nil, err
    	}

    	return k.(crypto.Signer), nil
    }

    return nil, fmt.Errorf("Bad PEM format type %v", block.Type)
}

func ReadPublicKey(file string) (crypto.PublicKey, error) {
	block, err := read_pem(file)

	if(err != nil){
		return nil, err
	}
    

    if(block.Type == "PUBLIC KEY"){
    	k, err := x509.ParsePKIXPublicKey(block.Bytes)

    	if(err != nil){
    		return nil, err
    	}

    	return k, nil
    }

    if(block.Type == "PRIVATE KEY"){
    	//special case been given a private key
    	//convert to a public key
    	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)

    	if(err != nil){
    		return nil, err
    	}

    	switch priv.(type) {
    	case *ecdsa.PrivateKey:
    		return priv.(*ecdsa.PrivateKey).Public(), nil
    	case ed25519.PrivateKey:
    		return priv.(ed25519.PrivateKey).Public(), nil
    	default:
    		return nil, fmt.Errorf("Unsupported private key supplied as a public key, cannot convert")
    	}
    }

    return nil, fmt.Errorf("Bad PEM format type %v", block.Type)
}