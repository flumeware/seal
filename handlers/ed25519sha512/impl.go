package ed25519sha512

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/flumeware/seal/format"
	"github.com/flumeware/seal/internal/hashstream"
)

const BlockType = "ed25519-sha512"

func SignStream(privkey ed25519.PrivateKey, stream *hashstream.Sha512Stream) (*format.SignatureBlock, error){
	key_id := privkey.Public().(ed25519.PublicKey)
	
	body := key_id

	body = append(body, stream.Digest()...)

	sig, err := privkey.Sign(rand.Reader, body, crypto.Hash(0))

	if(err != nil){
		return nil, fmt.Errorf("error during signing %w", err)
	}

	return &format.SignatureBlock{Type: BlockType, Body: sig}, nil
}

func VerifyStream(pubkey ed25519.PublicKey, block *format.SignatureBlock, stream *hashstream.Sha512Stream) bool{
	if(block.Type != BlockType){return false}
	body := pubkey
	body = append(body, stream.Digest()...)

	return ed25519.Verify(pubkey, body, block.Body)
}