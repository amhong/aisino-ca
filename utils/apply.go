package utils

import (
	"aisino-ca/raservice"
	"encoding/json"
	"fmt"
)

func ApplyCert(name string) (sigPemCert, sigPemKey, encPemCert, encPemPrikey string, err error) {
	url := "http://202.100.108.40:40001/XiZangCertServicesBeanService/XiZangCertServicesBean?wsdl"

	sigPemKey, pkcs10, _ := GenPkcs10(name, "", "", "", "", "", "", "")

	dn := GetDN(name, "", "", "", "", "")

	req := raservice.GenerateCertZzpt{
		Ns:   "com.aisino.hxra.client.services.XiZangCertServicesEndPoint",
		Arg0: "10000000000FED6A",
		Arg1: "1",
		Arg2: pkcs10,
		Arg3: dn,
		Arg4: "206",
		Arg5: "1825",
		Arg6: "0",
		Arg7: name,
		Arg8: "0",   //身份证
		Arg9: "111", //身份证号
	}

	certExection := map[string]string{"0.9.2342.19200300.100.1.1": name, "2.5.4.72": "user"}

	exect, err := json.Marshal(&certExection)

	req.Arg23 = string(exect)

	sigPemCert, encPemCert, encPemPrikey, err = raservice.ApplyCertificate(url, &req)
	if err != nil {
		return "", "", "", "", fmt.Errorf("apply cert failed: %s", err.Error())
	}

	return

}
