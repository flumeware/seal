//Copright 2022 simplesig authors
//Heavily inspired by age
package format

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

type SignatureBlock struct{
	Type string
	Args []string
	Body []byte
}

type Header struct{
	Signatures []*SignatureBlock
}

var b64 = base64.RawStdEncoding.Strict()

func DecodeString(s string) ([]byte, error) {
	//From age
	// CR and LF are ignored by DecodeString, but we don't want any malleability.
	if strings.ContainsAny(s, "\n\r") {
		return nil, errors.New(`unexpected newline character`)
	}
	return b64.DecodeString(s)
}

var signatureIntro = []byte("->")
var signatureOutro = []byte("<-")
var headerOutro = []byte("/----/")
const fileIdentifier = "kepler22b.uk/seal/v1\n"

func Parse(input io.Reader) (*Header, io.Reader, error){
	h := &Header{}

	buf := bufio.NewReader(input)

	line, err := buf.ReadString('\n')

	if(err != nil){
		return nil, nil, fmt.Errorf("Unable to reader file identifier line %w", err)
	}

	if(line != fileIdentifier){
		return nil, nil, fmt.Errorf("File is badly formatted, does not start with '%v'", fileIdentifier)
	}

	var sb *SignatureBlock

	//loop over the file and read the headers
	for{
		line, err := buf.ReadBytes('\n')

		if(err != nil){
			return nil, nil, fmt.Errorf("Error reading line %w", err)
		}

		//check if this is the final line of the header
		if(bytes.HasPrefix(line, headerOutro)){
			//all following data is the signed data
			break
		}

		//check if this is a signature block start line
		if(bytes.HasPrefix(line, signatureIntro)){
			if(sb != nil){
				//previous signature is not terminated
				//something has gone wrong
				//error
				return nil, nil, fmt.Errorf("Unterminated signature block at %v", string(line))
			}

			//construct a new signature
			sb = &SignatureBlock{}

			args := strings.Split(strings.TrimSuffix(string(line), "\n"), " ")

			sb.Type = args[1]
			sb.Args = args[2:]
			continue
		}

		if(bytes.HasPrefix(line, signatureOutro)){
			//this line is a sig outro
			//add the current signature block to the header
			h.Signatures = append(h.Signatures, sb)

			sb = nil //clear
			continue
		}

		if(sb != nil){
			//reading signature body
			//signature bodies are base64 encoded
			//line wrapping is not enforced
			b, err := DecodeString(strings.TrimSuffix(string(line), "\n"))

			if(err != nil){
				return nil, nil, fmt.Errorf("Error decoding signature block body at line '%v' %w", string(line), err)
			}

			sb.Body = append(sb.Body, b...)
		}
	}

	//return a reader for the remaining content of the file
	//input was a bufio, so just return it
	if buf == input {
		return h, buf, nil
	}
	
	//not a bufio input so need to add back the bytes which are still in the buffer
	buf_overread, err := buf.Peek(buf.Buffered())
	if err != nil {
		return nil, nil, fmt.Errorf("internal error: %w", err)
	}
	payload := io.MultiReader(bytes.NewReader(buf_overread), input)
	return h, payload, nil
}

func (s *SignatureBlock) Marshal(w io.Writer) error{
	//write the signature block out
	//add the intro
	if _, err := w.Write(signatureIntro); err != nil{
		return err
	}

	//write the type
	if _, err := io.WriteString(w, " "+s.Type); err != nil{
		return err
	}

	//write the other args
	for _, arg := range s.Args{
		if _, err :=  io.WriteString(w, " "+arg); err != nil{
			return err
		}
	}

	if _, err := io.WriteString(w, "\n"); err != nil{
		return err
	}

	//write the base64 encoded body
	if _, err := io.WriteString(w, b64.EncodeToString(s.Body)); err != nil{
		return err
	}
	//add the newline
	if _, err := io.WriteString(w, "\n"); err != nil{
		return err
	}

	//write the terminator
	if _, err := w.Write(signatureOutro); err != nil{
		return err
	}
	
	//add the newline
	if _, err := io.WriteString(w, "\n"); err != nil{
		return err
	}

	return nil
}

func (h *Header) Marshal(w io.Writer) error{
	//write the file header
	if _, err := io.WriteString(w, fileIdentifier); err != nil{
		return err
	}

	//write each signature block
	for _, s := range h.Signatures{
		if err := s.Marshal(w); err != nil{
			return err
		}
	}

	//add the header outro
	if _, err := w.Write(headerOutro); err != nil{
		return err
	}

	if _, err := io.WriteString(w, "\n"); err != nil{
		return err
	}


	return nil
}



