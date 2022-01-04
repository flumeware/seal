# v1 File Format

Each file consists of one or more signature blocks

Each signature block begins with '->' and contains a header which specifies:
 * The algorithm used to produce the signature
 * The identifies of the key used

It is followed by the bytes of the signature

A signature block is teminated by `<-`

After the signature blocks the header is terminated by a line consisting solely of `/----/` the following lines are the message data

If the signature block is detached then no data follows the `/----/` line

## Ed25519-SHA512 Signatures

For Ed25519 the key is short enough to be included directly so `KeyId` is identical to the Public Key
The signature is computed over `KeyId||SHA-512(MessageData)`

The Message is hashed using SHA-512 for simplicity in the case of very large data. This obviously reduces the security to that of SHA-512 with respect to collisions

## ECDSA-SHA512 Signatures

`KeyId` is now defined as `SHA-512(PublicKey)` where public key is the DER PKIX encoding of the public key

The signature is computed over `SHA512(KeyId||SHA-512(MessageData))` The signtaure is the ASN1 representation


## Example Output
```
kepler22b.uk/seal/v1
-> ed25519-sha512
ABM2/CLhcj3OBtA46mwRBeeZjD0z5ZkR1iQgj2ITE/SE+/qG7EHkScuYFLF+IwSFka2fNYxLfwTta0Pbf16eDA
<-
/----/
test message
```