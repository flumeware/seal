package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/flumeware/seal"
	"github.com/flumeware/seal/format"
	"github.com/flumeware/seal/handlers/ecdsasha512"
	"github.com/flumeware/seal/handlers/ed25519sha512"
	"github.com/flumeware/seal/internal/hashstream"
)

type arrayFlag []string

func (f *arrayFlag) String() string{
	return "-"
}

func (f *arrayFlag) Set(value string) error{
	*f = append(*f, value)
	return nil
}

func fatal_err(s string){
	fmt.Print(s,"\n")
	os.Exit(-1)
}

func main(){
	var do_sign = flag.Bool("s", false, "Sign input")
	var do_verify = flag.Bool("v", false, "Verify input")
	var detached_mode = flag.Bool("d", false, "If signing only output the signature data, if Verifying expects the signatures on stdin, and the -f option to specify the data file")
	var detatched_file = flag.String("f", "", "Path to data file for detached verification")

	var key_paths arrayFlag
	flag.Var(&key_paths, "k", "Path to key file, for signing this must be a private key file, for verification this must be a public key (can be repeated)")

	var output_path = flag.String("o", "", "Output to file")

	flag.Parse()

	if(*do_sign == false && *do_verify == false){
		fatal_err("No action specified either Sign (-s) or Verify (-v) must be supplied")
	}

	if(len(key_paths) == 0){
		fatal_err("No Keys supplied")
	}

	if(*do_sign){
		//sign the input
		sign(key_paths, *detached_mode, *output_path)
	}

	if(*do_verify){
		verify(key_paths, *detached_mode, *output_path, *detatched_file)
	}
}

func sign(key_paths []string, detached bool, output_path string){
	//load the private keys
	var keys []crypto.PrivateKey

	for _, p := range key_paths{
		k, err := seal.ReadPrivateKey(p)

		if(err != nil){
			fatal_err(fmt.Sprintf("Unable to load private key from '%v' error: %v", p, err))
		}

		keys = append(keys, k)
	}

	header := &format.Header{}

	//generate the sha512 hash stream
	sha512_stream := hashstream.NewSHA512Stream()

	attached_buffer := bytes.Buffer{}

	
	if(!detached){
		io.Copy(io.MultiWriter(sha512_stream, &attached_buffer), os.Stdin)
	}else{
		io.Copy(sha512_stream, os.Stdin)
	}

	sha512_stream.Close() //close the stream whcih computes the digest

	//loop over the loaded private keys and generate a signature from each
	for _, k := range keys{
		switch k.(type) {
		case *ecdsa.PrivateKey:
			//generate an ecdsa-sha512 signature
			sb, err := ecdsasha512.SignStream(k.(*ecdsa.PrivateKey), sha512_stream)

			if(err != nil){
				fatal_err(fmt.Sprintf("Error generating signature using ecdsa-sha512 %v", err))
			}

			header.Signatures = append(header.Signatures, sb)
			break
		case ed25519.PrivateKey:
			//generate an ed25519-sha512 signature
			sb, err := ed25519sha512.SignStream(k.(ed25519.PrivateKey), sha512_stream)

			if(err != nil){
				fatal_err(fmt.Sprintf("Error generating signature using ed25519-sha512 %v", err))
			}

			header.Signatures = append(header.Signatures, sb)
			break
		default:
			fatal_err("Unknown key type")
		}
	}

	var output io.Writer

	if(output_path == ""){
		//output to stdout
		output = os.Stdout
	}else{
		//output to a file
		var err error
		output, err = os.Create(output_path)

		if(err != nil){
			fatal_err(fmt.Sprintf("Error opening output file '%v' %v", output_path, err))
		}
	}

	header.Marshal(output)

	if(!detached){
		//attach the input data
		io.Copy(output, &attached_buffer)
	}
}

func verify(key_paths []string, detached bool, output_path string, detatched_file string){
	//read the public keys

	keys := make(map[string]crypto.PublicKey)

	for _, p := range key_paths{
		k, err := seal.ReadPublicKey(p)

		if(err != nil){
			fatal_err(fmt.Sprintf("Unable to load public key from '%v' error: %v", p, err))
		}

		keys[p] = k
	}

	//parse stdin
	header, message, err := format.Parse(os.Stdin)

	if(err != nil){
		fatal_err(fmt.Sprintf("Unable to parse stdin %v", err))
	}

	if(len(header.Signatures) == 0){
		fatal_err("Header does not include any signatures")
	}

	sha512_stream := hashstream.NewSHA512Stream()

	attached_buffer := bytes.Buffer{}

	if(detached){
		if(detatched_file == ""){
			fatal_err("Detatched mdoe specified but no file (-f) supplied")
		}
		//read the specified file
		f, err := os.Open(detatched_file)

		if(err != nil){
			fatal_err(fmt.Sprintf("Unable to open data file (-f) '%v' %v", detatched_file, err))
		}

		io.Copy(sha512_stream, f)

		f.Close()
	}else{
		//copy the message which was parsed into the sha stream and the attached buffer to be replayed at the end
		io.Copy(io.MultiWriter(sha512_stream, &attached_buffer), message)
	}

	sha512_stream.Close() //close to compute the digest

	valid_sigs := 0

	for path, k := range keys{
		vres := false
		switch k.(type) {
		case *ecdsa.PublicKey:
			vres = verify_ecdsa(path, k.(*ecdsa.PublicKey), header, sha512_stream)
		case ed25519.PublicKey:
			vres = verify_ed25519(path, k.(ed25519.PublicKey), header, sha512_stream)
		default:
			fatal_err("Unknown key type")
		}

		if(vres){
			valid_sigs += 1
		}
	}

	if(valid_sigs == 0){
		//no signatures verified
		fatal_err("Unable to verify any signatures using the supplied keys.\nEither the file has been tampered with or you do not have the correct keys to verify it")
	}

	if(!detached){
		fmt.Printf("\n   Signed Contents Follows:\n------------------------------\n%v", attached_buffer.String())
	}
}

func verify_ecdsa(key_path string, pk *ecdsa.PublicKey, hdr *format.Header, stream *hashstream.Sha512Stream) bool{
	for _, sb := range hdr.Signatures{
		if(sb.Type != ecdsasha512.BlockType){
			//not this type of signature
			continue
		}

		//verify the block
		res := ecdsasha512.VerifyStream(pk, sb, stream)

		if(res){
			fmt.Printf("Verified Signature using '%v'\n", key_path)
			return true
		}

		//if signature fails to verify this could just mean it was not signed by this key, so cannot say it was forged
	}

	return false
}

func verify_ed25519(key_path string, pk ed25519.PublicKey, hdr *format.Header, stream *hashstream.Sha512Stream) bool{
	for _, sb := range hdr.Signatures{
		if(sb.Type != ed25519sha512.BlockType){
			//not this type of signature
			continue
		}

		//verify the block
		res := ed25519sha512.VerifyStream(pk, sb, stream)

		if(res){
			fmt.Printf("Verified Signature using '%v'\n", key_path)
			return true
		}

		//if signature fails to verify this could just mean it was not signed by this key, so cannot say it was forged
	}

	return false
}