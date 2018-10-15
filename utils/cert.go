package utils

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sm2"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

func GetDN(name, ou, o, location, state, country string) string {
	dn := "CN=" + name
	if ou != "" {
		dn += ",OU=" + ou
	}
	if o != "" {
		dn += ",O=" + o
	}
	if location != "" {
		dn += ",L=" + location
	}
	if state != "" {
		dn += ",ST=" + state
	}
	if country != "" {
		dn += ",C=" + country
	}

	return dn
}

func GenPkcs10(name, ou, o, location, state, country, address, postcode string) (pemPrikey, pkcs10 string, err error) {
	alg := "sm2"
	//生成私钥
	var rsaPrivateKey *rsa.PrivateKey
	var ecdsaPrivateKey *ecdsa.PrivateKey
	var sm2PrivateKey *sm2.PrivateKey

	switch alg {
	case "rsa1024":
		rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 1024)
	case "rsa2048":
		rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ecdsa256":
		ecdsaPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "sm2":
		sm2PrivateKey, err = sm2.GenerateKey()
	default:
		return "", "", fmt.Errorf("alg invalid")
	}
	if err != nil {
		return "", "", fmt.Errorf("generate private key failed: %s", err.Error())

	}

	var priKeyDerStream []byte
	switch alg {
	case "rsa1024", "rsa2048":
		priKeyDerStream = x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
	case "ecdsa256":
		priKeyDerStream, err = x509.MarshalECPrivateKey(ecdsaPrivateKey)
		if err != nil {
			return "", "", fmt.Errorf("marshal privateKey failed: %s", err.Error())
		}
	case "sm2":
		priKeyDerStream, err = x509.MarshalSm2PrivateKey(sm2PrivateKey)
		if err != nil {
			return "", "", fmt.Errorf("marshal privateKey failed: %s", err.Error())
		}
	}

	//编码私钥
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: priKeyDerStream,
	}
	buffer := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(buffer, block)
	if err != nil {
		return "", "", fmt.Errorf("pem encode failed: %s", err.Error())
	}
	pemPrikey = buffer.String()

	//产生证书请求
	subject := pkix.Name{
		Country:            []string{country},
		Organization:       []string{o},
		OrganizationalUnit: []string{ou},
		Locality:           []string{location},
		Province:           []string{state},
		StreetAddress:      []string{address},
		PostalCode:         []string{postcode},
		CommonName:         name,
	}

	req := &x509.CertificateRequest{
		Subject: subject,
	}

	var pkcs10DerStream []byte
	switch alg {
	case "rsa1024", "rsa2048":
		pkcs10DerStream, err = x509.CreateCertificateRequest(rand.Reader, req, rsaPrivateKey)
	case "ecdsa256":
		pkcs10DerStream, err = x509.CreateCertificateRequest(rand.Reader, req, ecdsaPrivateKey)
	case "sm2":
		pkcs10DerStream, err = x509.CreateCertificateRequest(rand.Reader, req, sm2PrivateKey)
	}
	if err != nil {
		return "", "", fmt.Errorf("CreateCertificateRequest failed: %s", err.Error())
	}

	pkcs10 = base64.StdEncoding.EncodeToString(pkcs10DerStream)

	return
}

//把ca返回的base64编码的p7b证书转换为pem编码的证书
func ConvertCert(cert string) (pemCert string, err error) {
	//签名证书base64解码
	decodeBytes, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return "", fmt.Errorf("p7b cert base64 decode failed: %s", err.Error())
	}
	//签名证书pem编码
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: decodeBytes,
	}
	sigcert := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(sigcert, block)
	if err != nil {
		return "", fmt.Errorf("p7b cert pem encode failed: %s", err.Error())
	}

	//把p7b证书转换成pem证书
	pemCert, err = P7b2Pem(sigcert.String())
	if err != nil {
		return "", fmt.Errorf("P7b2Pem failed: %s", err.Error())
	}

	return
}

//把p7b格式证书转换为pem格式证书
func P7b2Pem(p7bCert string) (pemCert string, err error) {

	t := strconv.FormatInt(time.Now().UnixNano(), 10)
	inFile := filepath.Join("/tmp", "tmpCert"+t+".p7b")
	outFile := filepath.Join("/tmp", "tmpCert"+t+".cer")

	err = ioutil.WriteFile(inFile, []byte(p7bCert), 0666)
	if err != nil {
		return "", fmt.Errorf("WriteFile %s fail: %s", inFile, err.Error())
	}

	arg := "openssl pkcs7" + " -print_certs -in " + inFile + " -out " + outFile

	cmd := exec.Command("/bin/sh", "-c", arg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("exe cmd %s fail: %s", arg, string(out))
	}

	inbyte, err := ioutil.ReadFile(outFile)
	if err != nil {
		return "", fmt.Errorf("ReadFile %s fail: %s", outFile, err.Error())
	}
	pemCert = string(inbyte)

	//删除临时文件
	arg = "rm -rf " + inFile
	cmd = exec.Command("/bin/sh", "-c", arg)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("exe cmd %s fail: %s", arg, string(out))
	}

	arg = "rm -rf " + outFile
	cmd = exec.Command("/bin/sh", "-c", arg)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("exe cmd %s fail: %s", arg, string(out))
	}

	return
}

func Reverse(s []byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func RC4Crypt(key []byte, src []byte) (dist []byte, err error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("NewCipher failed: %s", err.Error())
	}

	dist = make([]byte, len(src))
	c.XORKeyStream(dist, src)

	return dist, nil
}

func UnpackEnvelop(EncryptedPrivateKeyBase64, EncryptedSessionKeyBase64 string, tmpPrivateKey *rsa.PrivateKey) (priKeyBytes []byte, err error) {
	//私钥密文base64解码
	EncryptedPrivateKey, err := base64.StdEncoding.DecodeString(EncryptedPrivateKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("EncryptedPrivateKey base64 decode failed: %s", err.Error())
	}

	//会话密钥base64解码
	EncryptedSessionKey, err := base64.StdEncoding.DecodeString(EncryptedSessionKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("EncryptedSessionKey base64 decode failed: %s", err.Error())
	}

	//翻转加密的会话密钥
	Reverse(EncryptedSessionKey)

	//解密会话密钥
	sessionKey, err := rsa.DecryptPKCS1v15(rand.Reader, tmpPrivateKey, EncryptedSessionKey)

	if err != nil {
		return nil, fmt.Errorf("decrypt session key failed: %s", err.Error())
	}

	//会话密钥派生rc4密钥
	h := md5.New()
	h.Write(sessionKey)
	rc4key := h.Sum(nil)

	//rc4密钥解密私钥
	dist, err := RC4Crypt(rc4key, EncryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key failed: %s", err.Error())
	}

	newDist := dist[28:60]

	return newDist, nil
}

func BuildPriKey(EncryptedPrivateKeyBase64, EncryptedSessionKeyBase64 string, tmpPrivateKey *rsa.PrivateKey) (pemPrivateKey string, err error) {
	keyPri32, err := UnpackEnvelop(EncryptedPrivateKeyBase64, EncryptedSessionKeyBase64, tmpPrivateKey)
	if err != nil {
		return "", fmt.Errorf("UnpackEnvelop failed: %s", err.Error())
	}

	d := new(big.Int).SetBytes(keyPri32)

	c := sm2.P256Sm2()
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(d.Bytes())

	prikeyBytes, err := x509.MarshalSm2PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("MarshalSm2PrivateKey failed: %s", err.Error())
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: prikeyBytes,
	}
	priKey := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(priKey, block)
	if err != nil {
		return "", fmt.Errorf("Pem encode failed: %s", err.Error())
	}

	return priKey.String(), nil
}

func RsaSign(origData string, privateKeyPem []byte, hash crypto.Hash) (sig string, err error) {
	//解析成RSA私钥
	block, _ := pem.Decode(privateKeyPem)
	prikey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("ParsePKCS1PrivateKey fail: %s", err.Error())
	}

	h := hash.New()
	h.Write([]byte(origData))
	digest := h.Sum(nil)

	s, err := rsa.SignPKCS1v15(nil, prikey, hash, digest)
	if err != nil {
		return "", fmt.Errorf("rsaSign SignPKCS1v15 fail: %s", err.Error())
	}
	sig = base64.StdEncoding.EncodeToString(s)
	return
}

func MarshalPublicKey(pub interface{}) ([]byte, error) {
	var publicKeyBytes []byte
	var err error

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(pkcs1PublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("x509: only RSA public keys supported")
	}

	return publicKeyBytes, nil
}

type pkcs1PublicKey struct {
	N *big.Int
	E int
}
