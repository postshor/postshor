package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
)

func main() {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	ct, _ := rsa.EncryptOAEP(nil, rand.Reader, &k.PublicKey, []byte("x"), nil)
	e, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cfg := &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}
	good := &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}}
	_, _, _, _ = ct, e, cfg, good
}
