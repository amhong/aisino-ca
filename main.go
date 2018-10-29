package main

import (
	"aisino-ca/cert"
	"fmt"
)

func main() {
	//sigPemCert, sigPemKey, encPemCert, encPemPrikey, err := utils.ApplyDoubleCert("zht", "aisino")
	//if err != nil {
	//	fmt.Println(err)
	//}
	//
	//fmt.Println("-----------------sigPemCert-----------------")
	//fmt.Println(sigPemCert)
	//fmt.Println("-----------------sigPemKey-----------------")
	//fmt.Println(sigPemKey)
	//fmt.Println("-----------------encPemCert-----------------")
	//fmt.Println(encPemCert)
	//fmt.Println("-----------------encPemPrikey-----------------")
	//fmt.Println(encPemPrikey)

	sigPemCert, sigPemKey, err := cert.ApplyTlsCert("test", "")
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("-----------------sigPemCert-----------------")
	fmt.Println(sigPemCert)
	fmt.Println("-----------------sigPemKey-----------------")
	fmt.Println(sigPemKey)

}
