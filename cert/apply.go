package cert

import (
	"aisino-ca/raservice"
	"aisino-ca/utils"
	"encoding/json"
	"fmt"
	"net"
)

const (
	//caUrl =  "http://202.100.108.14:20011/XiZangCertServicesBeanService/XiZangCertServicesBean?wsdl"
	caUrl          = "http://202.100.108.40:40001/XiZangCertServicesBeanService/XiZangCertServicesBean?wsdl"
	doubleTemplate = "206"
	singleTemplate = "205"
	//operatorSn = "20000000000172A2"
	operatorSn = "10000000000FED6A"

	OBJ_IP = "2.5.29.999.21"
)

func ApplyDoubleCert(name, o string) (sigPemCert, sigPemKey, encPemCert, encPemPrikey string, err error) {
	sigPemKey, pkcs10, _ := utils.GenPkcs10(name, "", o, "", "", "", "", "")

	dn := utils.GetDN(name, "", o, "", "", "")

	req := raservice.GenerateCertZzpt{
		Ns:   "com.aisino.hxra.client.services.XiZangCertServicesEndPoint",
		Arg0: operatorSn,
		Arg1: "1",
		Arg2: pkcs10,
		Arg3: dn,
		Arg4: doubleTemplate,
		Arg5: "1825",
		Arg6: "0",
		Arg7: name,
		Arg8: "0",   //身份证
		Arg9: "111", //身份证号
	}

	certExection := map[string]string{"0.9.2342.19200300.100.1.1": name, "2.5.4.72": "user"}

	exect, err := json.Marshal(&certExection)

	req.Arg23 = string(exect)

	sigPemCert, encPemCert, encPemPrikey, err = raservice.ApplyCertificate(caUrl, &req)
	if err != nil {
		return "", "", "", "", fmt.Errorf("apply cert failed: %s", err.Error())
	}

	return

}

func ApplySingleCert(name, o string) (sigPemCert, sigPemKey string, err error) {
	sigPemKey, pkcs10, _ := utils.GenPkcs10(name, "", o, "", "", "", "", "")

	dn := utils.GetDN(name, "", o, "", "", "")

	req := raservice.GenerateCertZzpt{
		Ns:   "com.aisino.hxra.client.services.XiZangCertServicesEndPoint",
		Arg0: operatorSn,
		Arg1: "0",
		Arg2: pkcs10,
		Arg3: dn,
		Arg4: singleTemplate,
		Arg5: "1825",
		Arg6: "0",
		Arg7: name,
		Arg8: "0",   //身份证
		Arg9: "111", //身份证号
	}

	//certExection := map[string]string{"0.9.2342.19200300.100.1.1": name, "2.5.4.72": "user"}
	//
	//exect, err := json.Marshal(&certExection)
	//
	//req.Arg23 = string(exect)

	sigPemCert, _, _, err = raservice.ApplyCertificate(caUrl, &req)
	if err != nil {
		return "", "", fmt.Errorf("apply cert failed: %s", err.Error())
	}

	return

}

func ApplyTlsCert(name, o string) (sigPemCert, sigPemKey string, err error) {
	sigPemKey, pkcs10, _ := utils.GenPkcs10(name, "", o, "", "", "", "", "")

	dn := utils.GetDN(name, "", o, "", "", "")

	//extMap := make(map[string]string)
	//extMap["0.9.2342.19200300.100.1.1"] = name
	//extMap["2.5.4.72"] = "user"
	//ext, _ := json.Marshal(extMap)

	ext, _ := GetEXT("192.168.20.111", name)

	req := raservice.GenerateCertZzpt{
		Ns:    "com.aisino.hxra.client.services.XiZangCertServicesEndPoint",
		Arg0:  operatorSn,
		Arg1:  "0",
		Arg2:  pkcs10,
		Arg3:  dn,
		Arg4:  singleTemplate,
		Arg5:  "1825",
		Arg6:  "0",
		Arg7:  name,
		Arg8:  "0",   //身份证
		Arg9:  "111", //身份证号
		Arg23: string(ext),
	}

	//certExection := map[string]string{"0.9.2342.19200300.100.1.1": name, "2.5.4.72": "user"}
	//
	//exect, err := json.Marshal(&certExection)
	//
	//req.Arg23 = string(exect)

	sigPemCert, _, _, err = raservice.ApplyCertificate(caUrl, &req)
	if err != nil {
		return "", "", fmt.Errorf("apply cert failed: %s", err.Error())
	}

	return

}

func GetEXT(ip, host string) ([]byte, error) {

	extMap := make(map[string]string, 1)
	if net.ParseIP(ip) != nil {
		extMap[OBJ_IP] = "IP=" + ip
	} else {
		extMap[OBJ_IP] = fmt.Sprintf("%s&%s", host, ip)
	}

	return json.Marshal(&extMap)
}
