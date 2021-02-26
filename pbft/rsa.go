package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
)

const (
	keystore = "/Users/dylen/workspace/gohome/src/github.com/dylenfu/consensus_examples/build/keystore"
)

func priKeyFormat(i int) string { return fmt.Sprintf("%s/N%d_RSA_PIV", keystore, i) }
func pubKeyFormat(i int) string { return fmt.Sprintf("%s/N%d_RSA_PUB", keystore, i) }

//如果当前目录下不存在目录Keys，则创建目录，并为各个节点生成rsa公私钥
func genRsaKeys() {
	for i := 0; i <= 4; i++ {
		if err := os.MkdirAll(keystore, os.ModePerm); err != nil {
			return
		}

		priv, pub := getKeyPair()
		writeFile(priKeyFormat(i), priv)
		writeFile(pubKeyFormat(i), pub)
	}
	fmt.Println("已为节点们生成RSA公私钥")
}

//生成rsa公私钥
func getKeyPair() (prvkey, pubkey []byte) {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	prvkey = pem.EncodeToMemory(block)
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	pubkey = pem.EncodeToMemory(block)
	return
}

//传入节点编号， 获取对应的公钥
func getPubKey(node string) []byte {
	idx, _ := strconv.Atoi(strings.TrimLeft(node, "N"))
	fn := pubKeyFormat(idx)
	key, err := ioutil.ReadFile(fn)
	if err != nil {
		log.Panic(err)
	}
	return key
}

//传入节点编号， 获取对应的私钥
func getPivKey(node string) []byte {
	idx, _ := strconv.Atoi(strings.TrimLeft(node, "N"))
	fn := priKeyFormat(idx)
	key, err := ioutil.ReadFile(fn)
	if err != nil {
		log.Panic(err)
	}
	return key
}

//数字签名
func Sign(digest string, node string) []byte {
	keyBytes := getPivKey(node)
	data, _ := hex.DecodeString(digest)
	h := sha256.New()
	h.Write(data)
	hashed := h.Sum(nil)
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(errors.New("private key error"))
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("ParsePKCS8PrivateKey err", err)
		panic(err)
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		fmt.Printf("Error from signing: %s\n", err)
		panic(err)
	}

	return signature
}

//签名验证
func Verify(digest string, signData []byte, node string) error {
	keyBytes := getPubKey(node)
	data, _ := hex.DecodeString(digest)
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return fmt.Errorf("public key error")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	hashed := sha256.Sum256(data)
	if err := rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signData); err != nil {
		return err
	}
	return nil
}

func writeFile(fn string, content []byte) {
	file, err := os.OpenFile(fn, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		log.Panic(err)
	}
	defer file.Close()
	file.Write(content)
}
