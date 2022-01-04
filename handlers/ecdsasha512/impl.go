package ecdsasha512

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"fmt"

	"github.com/flumeware/seal/format"
	"github.com/flumeware/seal/internal/hashstream"
)

func key_id(k *ecdsa.PublicKey) ([]byte, error){
	b, err := x509.MarshalPKIXPublicKey(k)


	return sha512_hash(b), err
}

func sha512_hash(d []byte) []byte{
	h := sha512.New()

	h.Write(d)

	return h.Sum([]byte{})
}

const BlockType = "ecdsa-sha512"

func SignStream(privkey *ecdsa.PrivateKey, stream *hashstream.Sha512Stream) (*format.SignatureBlock, error){
	body, err := key_id(privkey.Public().(*ecdsa.PublicKey))

	if(err != nil){
		return nil, fmt.Errorf("error computing key id %w", err)
	}

	body = append(body, stream.Digest()...)

	sig, err := ecdsa.SignASN1(rand.Reader, privkey, sha512_hash(body))

	if(err != nil){
		return nil, fmt.Errorf("error during signing %w", err)
	}

	return &format.SignatureBlock{Type: BlockType, Body: sig}, nil
}

func VerifyStream(pubkey *ecdsa.PublicKey, block *format.SignatureBlock, stream *hashstream.Sha512Stream) bool{
	if(block.Type != BlockType){return false}

	body, err := key_id(pubkey)

	if(err != nil){
		return false
	}

	body = append(body, stream.Digest()...)

	return ecdsa.VerifyASN1(pubkey, sha512_hash(body), block.Body)
}