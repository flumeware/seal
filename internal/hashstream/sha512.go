package hashstream

import "hash"
import "crypto/sha512"
import "fmt"

type Sha512Stream struct{
	h hash.Hash
	digest []byte
	closed bool
}

func NewSHA512Stream() *Sha512Stream{
	s := &Sha512Stream{h: sha512.New()}

	return s
}
	
//write data to the hash function
func (s *Sha512Stream) Write(p []byte) (n int, err error){
	if(s.closed){
		return 0, fmt.Errorf("stream is closed")
	}
	return s.h.Write(p)
}

func (s *Sha512Stream) Close() error{
	s.closed = true
	s.digest = s.h.Sum([]byte{})
	return nil
}

func (s *Sha512Stream) Digest() []byte{
	return s.digest
}