package raservice

import (
	"aisino-ca/utils"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/xml"
	"fmt"
)

func ApplyCertificate(url string, req *GenerateCertZzpt) (sigPemCert, encPemCert, encPemPrikey string, err error) {

	tmpRSAKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	pubKeyDerStream, _ := utils.MarshalPublicKey(&tmpRSAKey.PublicKey)
	tmpKeyBASE64 := base64.StdEncoding.EncodeToString(pubKeyDerStream)

	req.Arg24 = tmpKeyBASE64

	//申请证书
	service := NewXiZangCertServicesBean(url, true, nil)
	respGenCert, err := service.GenerateCertZzpt(req)
	if err != nil {
		return "", "", "", fmt.Errorf("generate cert failed: %s", err.Error())
	}

	//解析xml响应数据
	certResp := ApplyUpdateCertResp{}
	err = xml.Unmarshal([]byte(respGenCert.Return_), &certResp)
	if err != nil {
		return "", "", "", fmt.Errorf("unmarshal xml response failed: %s", err.Error())
	}
	if certResp.Success == "0" {
		return "", "", "", fmt.Errorf("apply cert failed: %s", certResp.Msg)
	}

	if req.Arg1 == "1" {
		encPemCert, err = utils.ConvertCert(certResp.Dcert)
		if err != nil {
			return "", "", "", fmt.Errorf("cnvert p7b cert to pem cert failed: %s", err.Error())

		}
		//解析数字信封获取加密私钥
		encPemPrikey, err = utils.BuildPriKey(certResp.EncryptedPrivateKey, certResp.EncryptedSessionKey, tmpRSAKey)
		if err != nil {
			return "", "", "", fmt.Errorf("unpack envelop failed: %s", err.Error())
		}
	}

	sigPemCert, err = utils.ConvertCert(certResp.Scert)
	if err != nil {
		return "", "", "", fmt.Errorf("cnvert p7b cert to pem cert failed: %s", err.Error())
	}

	return
}

func RevokeCertificate(orgUrl, certSn string) error {

	reason := int32(2) // 0: "密钥泄密";1:"CA泄密";2:"从属关系改变";3:"证书被取代";4:"操作终止";5:"从CRL删除";其他数字: "不明原因"

	//注销证书
	service := NewXiZangCertServicesBean(orgUrl, false, nil)
	reqRevokeCert := RevokeCert{
		Ns:   "com.aisino.hxra.client.services.XiZangCertServicesEndPoint",
		Arg0: certSn,
		Arg1: reason,
	}
	respRevokeCert, err := service.RevokeCert(&reqRevokeCert)
	if err != nil {
		return fmt.Errorf("revoke cert failed: %s", err.Error())
	}

	//解析xml响应数据
	resp := BaseResp{}
	err = xml.Unmarshal([]byte(respRevokeCert.Return_), &resp)
	if err != nil {
		return fmt.Errorf("unmarshal xml response failed: %s", err.Error())
	}
	if resp.Status == "0" {
		return fmt.Errorf("RevokeCertByOper failed: %s", resp.Msg)
	}

	return nil
}

type ApplyUpdateCertResp struct {
	Success             string `xml:",omitempty"`
	Msg                 string `xml:",omitempty"`
	Scert               string `xml:",omitempty"`
	Dcert               string `xml:",omitempty"`
	EncryptedPrivateKey string `xml:",omitempty"`
	EncryptedSessionKey string `xml:",omitempty"`
}

type BaseResp struct {
	Status string `xml:",omitempty"`
	Msg    string `xml:",omitempty"`
}
