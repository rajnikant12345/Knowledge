package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"math/big"
)

type PublicKey struct {
	Modulus  *big.Int
	Exponent *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
}

func Encrypt( in []byte , pub PublicKey ) []byte {
	messageInt := new(big.Int).SetBytes(in)

	//CT = POW(M,E) Mod N
	ct := new(big.Int).Exp(messageInt, pub.Exponent, pub.Modulus)
	return ct.Bytes()
}

func Decrypt( ct []byte , key *PrivateKey ) []byte {
	ctInt := new(big.Int).SetBytes(ct)

	//M = POW(CT,D) Mod N
	out := new(big.Int).Exp(ctInt, key.D, key.Modulus)
	return out.Bytes()
}

func EncryptPrivate( in []byte , priv *PrivateKey ) []byte {
	messageInt := new(big.Int).SetBytes(in)

	//CT = POW(M,D) Mod N
	ct := new(big.Int).Exp(messageInt, priv.D, priv.Modulus)
	return ct.Bytes()
}

func DecryptPublic( ct []byte , key *PublicKey ) []byte {
	ctInt := new(big.Int).SetBytes(ct)

	//M = POW(CT,E) Mod N
	out := new(big.Int).Exp(ctInt, key.Exponent, key.Modulus)
	return out.Bytes()
}

func GenerateKey( bitSize int ) (*PrivateKey,error) {
	for {
		bigOne := new(big.Int).SetInt64(1)

		//calculate first prime number
		p, err := rand.Prime(rand.Reader, bitSize/2)
		if err != nil {
			return nil,err
		}

		//calculate second prime number
		q, err := rand.Prime(rand.Reader, bitSize/2)
		if err != nil {
			return nil,err
		}


		pub := PublicKey{}

		//choose and exponent 65537 is chosen by most of the crypt libraries
		pub.Exponent = new(big.Int).SetInt64(65537)

		//calculate N = p x q
		pub.Modulus = new(big.Int).Mul(p, q)

		//calculate p-1
		pMinusOne := new(big.Int).Sub(p, bigOne)

		//calculate q-1
		qMinusOne := new(big.Int).Sub(q, bigOne)

		// calculate PHI(N) = (p-1) x (q-1)
		phiN := new(big.Int).Mul(pMinusOne, qMinusOne)

		priv := &PrivateKey{}
		priv.PublicKey = pub

		//calculate D, the private component, known to the owner only
		priv.D = new(big.Int).ModInverse(pub.Exponent, phiN)
		if priv.D != nil {
			return priv,nil
		}
	}
}

func getPrivateKeyFromBase64( in string  ) (*PrivateKey,error) {
	js,err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return nil, err
	}
	p := &PrivateKey{}
	err = json.Unmarshal(js, p)
	if err != nil {
		return nil, err
	}
	return p,nil
}

func getPublicKeyFromBase64( in string  ) (*PublicKey,error) {
	js,err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return nil, err
	}
	p := &PublicKey{}
	err = json.Unmarshal(js, p)
	if err != nil {
		return nil, err
	}
	return p,nil
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: <command>","command can be: generateKey , encrypt , decrypt , encryptPrivate, decryptPublic")
		return
	}

	command := os.Args[1]
	switch command {
	case "generateKey":
		k,err := GenerateKey(2048)
		if err != nil {
			panic(err)
		}
		pk,err := json.Marshal(k)
		if err != nil {
			panic(err)
		}
		pubKey,err := json.Marshal(k.PublicKey)
		if err != nil {
			panic(err)
		}
		fmt.Println("------------------------------------------------Please Save Them In A File------------ -----------------------------------------")
		fmt.Println( "PrivateKey Bytes:",base64.StdEncoding.EncodeToString(pk))
		fmt.Println("--------------------------------------------------------------------------------------------------------------------------------")
		fmt.Println("Public Key Bytes:",base64.StdEncoding.EncodeToString(pubKey))
		fmt.Println("--------------------------------------------------------------------------------------------------------------------------------")

	case "encrypt":
		if len(os.Args) < 4 {
			fmt.Println("please supply public key and message as arguments")
		}
		key := os.Args[2]
		message := os.Args[3]
		pub,err := getPublicKeyFromBase64(key)
		if err != nil {
			panic(err)
		}
		cipherText := Encrypt([]byte(message),*pub)
		fmt.Println("Encrypted message:",base64.StdEncoding.EncodeToString(cipherText))
	case "decrypt":
		if len(os.Args) < 4 {
			fmt.Println("please supply private key and message as arguments")
		}
		key := os.Args[2]
		ct,err := base64.StdEncoding.DecodeString(os.Args[3])
		if err != nil {
			panic(err)
		}
		pri,err := getPrivateKeyFromBase64(key)
		if err != nil {
			panic(err)
		}
		msg := Decrypt(ct,pri)
		fmt.Println("Decrypted message:",string(msg))
	case "encrypt-priv":
		if len(os.Args) < 4 {
			fmt.Println("please supply private key and message as arguments")
		}
		key := os.Args[2]
		message := os.Args[3]
		priv,err := getPrivateKeyFromBase64(key)
		if err != nil {
			panic(err)
		}
		cipherText := EncryptPrivate([]byte(message), priv)
		fmt.Println("Encrypted message:",base64.StdEncoding.EncodeToString(cipherText))
	case "decrypt-pub":
		if len(os.Args) < 4 {
			fmt.Println("please supply public key and message as arguments")
		}
		key := os.Args[2]
		ct,err := base64.StdEncoding.DecodeString(os.Args[3])
		if err != nil {
			panic(err)
		}
		pub,err := getPublicKeyFromBase64(key)
		if err != nil {
			panic(err)
		}
		msg := DecryptPublic(ct,pub)
		fmt.Println("Decrypted message:",string(msg))
	}
}
