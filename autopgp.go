// Copyright 2013 Alexander Winston
// All rights reserved.

package main

import (
	"bytes"
	"crypto"
	"flag"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
	_ "golang.org/x/crypto/ripemd160"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

var cipherToCipherNameMapping = []struct {
	id   packet.CipherFunction
	name string
}{
	{packet.Cipher3DES, "3DES"},
	{packet.CipherCAST5, "CAST5"},
	{packet.CipherAES128, "AES"},
	{packet.CipherAES192, "AES192"},
	{packet.CipherAES256, "AES256"},
}

func cipherIdToString(id packet.CipherFunction) (name string) {
	for _, m := range cipherToCipherNameMapping {
		if m.id == id {
			return m.name
		}
	}

	return ""
}

func main() {
	compatPtr := flag.Bool("compat", false, "prefer 3DES and SHA-1")
	keyPtr := flag.String("key", "", "the public key file to import")
	inputPtr := flag.String("input", "", "the plaintext file to read from")
	outputPtr := flag.String("output", "", "the ciphertext file to write to")
	flag.Parse()

	// Read in the public key.
	armoredKeyFile, err := os.Open(*keyPtr)
	if err != nil {
		log.Panic(err)
	}
	defer armoredKeyFile.Close()

	armoredKeyFileReader, err := armor.Decode(armoredKeyFile)
	if err != nil {
		log.Panic(err)
	}
	decodedKeyFileReader := packet.NewReader(armoredKeyFileReader.Body)

	decodedKey, err := openpgp.ReadEntity(decodedKeyFileReader)
	if err != nil {
		log.Panic(err)
	}

	log.Printf("Using public key with fingerprint %X\n", decodedKey.PrimaryKey.Fingerprint)

	// Set up the encryption options.
	encrypted := new(bytes.Buffer)

	content, err := ioutil.ReadFile(*inputPtr)
	if err != nil {
		log.Panic(err)
	} else {
		log.Println("Encrypting plaintext file", *inputPtr)
	}

	var cfg packet.Config
	if *compatPtr == true {
		cfg.DefaultCipher = packet.Cipher3DES
		cfg.DefaultHash = crypto.SHA1
	} else {
		cfg.DefaultCipher = packet.CipherAES256
		cfg.DefaultHash = crypto.SHA512
	}

	fh := openpgp.FileHints{
		IsBinary: true,
		FileName: filepath.Base(*inputPtr),
	}

	enc, err := openpgp.Encrypt(encrypted, []*openpgp.Entity{decodedKey}, nil, &fh, &cfg)
	if err != nil {
		log.Panic(err)
	}

	hashId, _ := s2k.HashToHashId(cfg.Hash())
	hashName, _ := s2k.HashIdToString(hashId)
	cipherName := cipherIdToString(cfg.Cipher())
	log.Println("Using hash", hashName)
	log.Println("Using cipher", cipherName)

	// Encrypt the contents.
	_, err = enc.Write([]byte(content))
	if err != nil {
		log.Panic(err)
	}

	// Close the file.
	enc.Close()

	// Write the ciphertext file.
	err = ioutil.WriteFile(*outputPtr, encrypted.Bytes(), 0400)
	if err != nil {
		log.Panic(err)
	} else {
		log.Println("Wrote ciphertext file", *outputPtr)
	}
}
