package raservice

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fabricMgtApi/config"
	"fabricMgtApi/utils/raservice"

	"aisino-ca/utils"
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
	//url := "http://202.100.108.40:40001/XiZangCertServicesBeanService/XiZangCertServicesBean?wsdl"
	service := NewXiZangCertServicesBean(url, false, nil)
	respGenCert, err := service.GenerateCertZzpt(req)
	if err != nil {
		return "", "", "", fmt.Errorf("generate cert failed: %s", err.Error())
	}

	//解析xml响应数据
	certResp := raservice.ApplyUpdateCertResp{}
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

func UpdateCertificate(orgUrl string, req *UpdateCertV2, isDouble bool) (sigPemCert, encPemCert, encPemPrikey string, err error) {
	service := NewXiZangCertServicesBean(orgUrl, false, nil)

	certSn := req.Arg2 //证书序列号
	operatorSn := config.GetOperatorSn()
	privateKeyPem := config.GetOperatorPrikey()

	//生成请求的签名参数:sig:约定原文的签名值，目前原文是"xzra"+"||"+sn+"||"+operSn五者的字符串拼接
	sig, err := utils.RsaSign("xzra||"+certSn+"||"+operatorSn, privateKeyPem, crypto.SHA1)
	if err != nil {
		return "", "", "", err
	}

	//授权证书可以更新
	reqModifyUpdateStatus := ModifyUpdateStatusV2{
		Ns:   "com.aisino.hxra.client.services.XiZangCertServicesEndPoint",
		Arg0: certSn,
		Arg1: "1", //status:要修改的权限状态值。0表示拒绝更新，1表示允许更新
		Arg2: operatorSn,
		Arg3: sig,
	}
	respModifyUpdateStatus, err := service.ModifyUpdateStatusV2(&reqModifyUpdateStatus)
	if err != nil {
		return "", "", "", fmt.Errorf("ModifyUpdateStatusV2 failed: %s", err.Error())
	}

	//解析xml响应数据
	resp := BaseResp{}
	err = xml.Unmarshal([]byte(respModifyUpdateStatus.Return_), &resp)
	if err != nil {
		return "", "", "", fmt.Errorf("unmarshal xml response failed: %s", err.Error())
	}
	if resp.Status != "1" {
		return "", "", "", fmt.Errorf("ModifyUpdateStatus failed: %s", resp.Msg)
	}

	req.Arg0 = operatorSn

	//生成请求的签名参数:sig:约定原文的签名值，目前是原文是"xzca"||sn||p10String
	req.Arg5, err = utils.RsaSign("xzca||"+certSn+"||"+req.Arg1, privateKeyPem, crypto.SHA1)
	if err != nil {
		return "", "", "", err
	}

	//todo:双证书的更新，需要产生临时加密公钥：req.Arg4
	var tmpRSAKey *rsa.PrivateKey
	if isDouble { //申请双证书
		//产生临时加密公钥: rsa1024
		var err error
		tmpRSAKey, err = rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return "", "", "", fmt.Errorf("generate template rsa key failed: %s", err.Error())
		}

		//编码公钥
		pubKeyDerStream, err := utils.MarshalPublicKey(&tmpRSAKey.PublicKey)
		//x509.MarshalPKIXPublicKey(&tmpRSAKey.PublicKey)
		if err != nil {
			return "", "", "", fmt.Errorf("MarshalPKIXPublicKey failed: %s", err.Error())
		}
		for _, v := range pubKeyDerStream {
			fmt.Printf("%02x ", v)
		}
		req.Arg4 = base64.StdEncoding.EncodeToString(pubKeyDerStream)
	}

	//更新证书
	respUpdateCert, err := service.UpdateCertV2(req)
	if err != nil {
		return "", "", "", fmt.Errorf("update cert failed: %s", err.Error())
	}

	//解析xml响应数据
	certResp := ApplyUpdateCertResp{}
	err = xml.Unmarshal([]byte(respUpdateCert.Return_), &certResp)
	if err != nil {
		return "", "", "", fmt.Errorf("unmarshal xml response failed: %s", err.Error())
	}
	if certResp.Success == "0" {
		return "", "", "", fmt.Errorf("apply cert failed: %s", certResp.Msg)
	}

	sigPemCert, err = utils.ConvertCert(certResp.Scert)
	if err != nil {
		return "", "", "", fmt.Errorf("convert p7b cert to pem cert failed: %s", err.Error())
	}

	//todo:双证书的需要用临时加密公钥(req.Arg4)解密加密私钥
	if isDouble {
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
