package raservice

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"time"
)

// against "unused imports"
var _ time.Time
var _ xml.Name

type RevokeCertByOper struct {
	//XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint revokeCertByOper"`
	XMLName struct{} `xml:"q0:revokeCertByOper"`
	Ns      string   `xml:"xmlns:q0,attr"`

	Arg0 string `xml:"arg0,omitempty"`

	Arg1 int32 `xml:"arg1,omitempty"`

	Arg2 string `xml:"arg2,omitempty"`

	Arg3 string `xml:"arg3,omitempty"`
}

type RevokeCertByOperResponse struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint revokeCertByOperResponse"`

	Return_ string `xml:"return,omitempty"`
}

type RevokeCert struct {
	//XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint revokeCert"`
	XMLName struct{} `xml:"q0:revokeCert"`
	Ns      string   `xml:"xmlns:q0,attr"`

	Arg0 string `xml:"arg0,omitempty"`

	Arg1 int32 `xml:"arg1,omitempty"`
}

type RevokeCertResponse struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint revokeCertResponse"`

	Return_ string `xml:"return,omitempty"`
}

type GetUsbKeyPwd struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint getUsbKeyPwd"`

	Arg0 string `xml:"arg0,omitempty"`
}

type GetUsbKeyPwdResponse struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint getUsbKeyPwdResponse"`

	Return_ string `xml:"return,omitempty"`
}

type ModifyUpdateStatusV2 struct {
	//XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint modifyUpdateStatusV2"`
	XMLName struct{} `xml:"q0:modifyUpdateStatusV2"`
	Ns      string   `xml:"xmlns:q0,attr"`

	Arg0 string `xml:"arg0,omitempty"`

	Arg1 string `xml:"arg1,omitempty"`

	Arg2 string `xml:"arg2,omitempty"`

	Arg3 string `xml:"arg3,omitempty"`
}

type ModifyUpdateStatusV2Response struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint modifyUpdateStatusV2Response"`

	Return_ string `xml:"return,omitempty"`
}

type GetSubject struct {
	//XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint getSubject"`
	XMLName struct{} `xml:"q0:getSubject"`
	Ns      string   `xml:"xmlns:q0,attr"`

	Arg0 string `xml:"arg0,omitempty"`
}

type GetSubjectResponse struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint getSubjectResponse"`

	Return_ string `xml:"return,omitempty"`
}

type CheckUpdateStatus struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint checkUpdateStatus"`

	Arg0 string `xml:"arg0,omitempty"`
}

type CheckUpdateStatusResponse struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint checkUpdateStatusResponse"`

	Return_ string `xml:"return,omitempty"`
}

type GenerateEventCert struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint generateEventCert"`

	Arg0 string `xml:"arg0,omitempty"`

	Arg1 string `xml:"arg1,omitempty"`

	Arg2 string `xml:"arg2,omitempty"`

	Arg3 string `xml:"arg3,omitempty"`

	Arg4 string `xml:"arg4,omitempty"`

	Arg5 string `xml:"arg5,omitempty"`

	Arg6 string `xml:"arg6,omitempty"`

	Arg7 string `xml:"arg7,omitempty"`

	Arg8 string `xml:"arg8,omitempty"`

	Arg9 string `xml:"arg9,omitempty"`

	Arg10 string `xml:"arg10,omitempty"`

	Arg11 string `xml:"arg11,omitempty"`

	Arg12 string `xml:"arg12,omitempty"`
}

type GenerateEventCertResponse struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint generateEventCertResponse"`

	Return_ string `xml:"return,omitempty"`
}

type GenerateCertLs struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint generateCertLs"`

	Arg0 string `xml:"arg0,omitempty"`

	Arg1 string `xml:"arg1,omitempty"`

	Arg2 string `xml:"arg2,omitempty"`

	Arg3 string `xml:"arg3,omitempty"`

	Arg4 string `xml:"arg4,omitempty"`

	Arg5 string `xml:"arg5,omitempty"`

	Arg6 string `xml:"arg6,omitempty"`

	Arg7 string `xml:"arg7,omitempty"`

	Arg8 string `xml:"arg8,omitempty"`

	Arg9 string `xml:"arg9,omitempty"`

	Arg10 string `xml:"arg10,omitempty"`

	Arg11 string `xml:"arg11,omitempty"`

	Arg12 string `xml:"arg12,omitempty"`

	Arg13 string `xml:"arg13,omitempty"`

	Arg14 string `xml:"arg14,omitempty"`

	Arg15 string `xml:"arg15,omitempty"`

	Arg16 string `xml:"arg16,omitempty"`

	Arg17 string `xml:"arg17,omitempty"`

	Arg18 string `xml:"arg18,omitempty"`

	Arg19 string `xml:"arg19,omitempty"`

	Arg20 string `xml:"arg20,omitempty"`

	Arg21 string `xml:"arg21,omitempty"`

	Arg22 string `xml:"arg22,omitempty"`

	Arg23 string `xml:"arg23,omitempty"`
}

type GenerateCertLsResponse struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint generateCertLsResponse"`

	Return_ string `xml:"return,omitempty"`
}

type GenerateCert struct {
	//XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint generateCert"`

	XMLName struct{} `xml:"q0:generateCert"`
	Ns      string   `xml:"xmlns:q0,attr"`

	Arg0 string `xml:"arg0,omitempty"`

	Arg1 string `xml:"arg1,omitempty"`

	Arg2 string `xml:"arg2,omitempty"`

	Arg3 string `xml:"arg3,omitempty"`

	Arg4 string `xml:"arg4,omitempty"`

	Arg5 string `xml:"arg5,omitempty"`

	Arg6 string `xml:"arg6,omitempty"`

	Arg7 string `xml:"arg7,omitempty"`

	Arg8 string `xml:"arg8,omitempty"`

	Arg9 string `xml:"arg9,omitempty"`

	Arg10 string `xml:"arg10,omitempty"`

	Arg11 string `xml:"arg11,omitempty"`

	Arg12 string `xml:"arg12,omitempty"`

	Arg13 string `xml:"arg13,omitempty"`

	Arg14 string `xml:"arg14,omitempty"`

	Arg15 string `xml:"arg15,omitempty"`

	Arg16 string `xml:"arg16,omitempty"`

	Arg17 string `xml:"arg17,omitempty"`

	Arg18 string `xml:"arg18,omitempty"`

	Arg19 string `xml:"arg19,omitempty"`

	Arg20 string `xml:"arg20,omitempty"`

	Arg21 string `xml:"arg21,omitempty"`

	Arg22 string `xml:"arg22,omitempty"`

	Arg23 string `xml:"arg23,omitempty"`
}

type GenerateCertResponse struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint generateCertResponse"`

	Return_ string `xml:"return,omitempty"`
}

type GenerateCertZzpt struct {
	//XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint generateCertZzpt"`

	XMLName struct{} `xml:"q0:generateCertZzpt"`
	Ns      string   `xml:"xmlns:q0,attr"`

	Arg0 string `xml:"arg0,omitempty"`

	Arg1 string `xml:"arg1,omitempty"`

	Arg2 string `xml:"arg2,omitempty"`

	Arg3 string `xml:"arg3,omitempty"`

	Arg4 string `xml:"arg4,omitempty"`

	Arg5 string `xml:"arg5,omitempty"`

	Arg6 string `xml:"arg6,omitempty"`

	Arg7 string `xml:"arg7,omitempty"`

	Arg8 string `xml:"arg8,omitempty"`

	Arg9 string `xml:"arg9,omitempty"`

	Arg10 string `xml:"arg10,omitempty"`

	Arg11 string `xml:"arg11,omitempty"`

	Arg12 string `xml:"arg12,omitempty"`

	Arg13 string `xml:"arg13,omitempty"`

	Arg14 string `xml:"arg14,omitempty"`

	Arg15 string `xml:"arg15,omitempty"`

	Arg16 string `xml:"arg16,omitempty"`

	Arg17 string `xml:"arg17,omitempty"`

	Arg18 string `xml:"arg18,omitempty"`

	Arg19 string `xml:"arg19,omitempty"`

	Arg20 string `xml:"arg20,omitempty"`

	Arg21 string `xml:"arg21,omitempty"`

	Arg22 string `xml:"arg22,omitempty"`

	Arg23 string `xml:"arg23,omitempty"`

	Arg24 string `xml:"arg24,omitempty"`
}

type GenerateCertZzptResponse struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint generateCertZzptResponse"`

	Return_ string `xml:"return,omitempty"`
}

type ReissueCert struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint reissueCert"`

	Arg0 string `xml:"arg0,omitempty"`

	Arg1 string `xml:"arg1,omitempty"`

	Arg2 string `xml:"arg2,omitempty"`

	Arg3 string `xml:"arg3,omitempty"`

	Arg4 string `xml:"arg4,omitempty"`
}

type ReissueCertResponse struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint reissueCertResponse"`

	Return_ string `xml:"return,omitempty"`
}

type ModifyUpdateStatus struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint modifyUpdateStatus"`

	Arg0 string `xml:"arg0,omitempty"`

	Arg1 string `xml:"arg1,omitempty"`

	Arg2 string `xml:"arg2,omitempty"`
}

type ModifyUpdateStatusResponse struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint modifyUpdateStatusResponse"`

	Return_ bool `xml:"return,omitempty"`
}

type UpdateCert struct {
	//XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint updateCert"`
	XMLName struct{} `xml:"q0:updateCert"`
	Ns      string   `xml:"xmlns:q0,attr"`

	Arg0 string `xml:"arg0,omitempty"`

	Arg1 string `xml:"arg1,omitempty"`

	Arg2 string `xml:"arg2,omitempty"`

	Arg3 string `xml:"arg3,omitempty"`

	Arg4 string `xml:"arg4,omitempty"`
}

type UpdateCertResponse struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint updateCertResponse"`

	Return_ string `xml:"return,omitempty"`
}

type UpdateCertV2 struct {
	//XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint updateCert"`
	XMLName struct{} `xml:"q0:updateCertV2"`
	Ns      string   `xml:"xmlns:q0,attr"`

	Arg0 string `xml:"arg0,omitempty"` //opertatorSn

	Arg1 string `xml:"arg1,omitempty"` //p10String

	Arg2 string `xml:"arg2,omitempty"` //sn

	Arg3 string `xml:"arg3,omitempty"` //dn

	Arg4 string `xml:"arg4,omitempty"` //tempPubKey

	Arg5 string `xml:"arg5,omitempty"` //sig

	Arg6 string `xml:"arg6,omitempty"` //exts
}

type UpdateCertV2Response struct {
	XMLName xml.Name `xml:"com.aisino.hxra.client.services.XiZangCertServicesEndPoint updateCertV2Response"`

	Return_ string `xml:"return,omitempty"`
}

type XiZangCertServicesBean struct {
	client *SOAPClient
}

func NewXiZangCertServicesBean(url string, tls bool, auth *BasicAuth) *XiZangCertServicesBean {
	if url == "" {
		url = ""
	}
	client := NewSOAPClient(url, tls, auth)

	return &XiZangCertServicesBean{
		client: client,
	}
}

func (service *XiZangCertServicesBean) AddHeader(header interface{}) {
	service.client.AddHeader(header)
}

// Backwards-compatible function: use AddHeader instead
func (service *XiZangCertServicesBean) SetHeader(header interface{}) {
	service.client.AddHeader(header)
}

func (service *XiZangCertServicesBean) GetSubject(request *GetSubject) (*GetSubjectResponse, error) {
	response := new(GetSubjectResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *XiZangCertServicesBean) CheckUpdateStatus(request *CheckUpdateStatus) (*CheckUpdateStatusResponse, error) {
	response := new(CheckUpdateStatusResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *XiZangCertServicesBean) ModifyUpdateStatus(request *ModifyUpdateStatus) (*ModifyUpdateStatusResponse, error) {
	response := new(ModifyUpdateStatusResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *XiZangCertServicesBean) ModifyUpdateStatusV2(request *ModifyUpdateStatusV2) (*ModifyUpdateStatusV2Response, error) {
	response := new(ModifyUpdateStatusV2Response)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *XiZangCertServicesBean) UpdateCert(request *UpdateCert) (*UpdateCertResponse, error) {
	response := new(UpdateCertResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *XiZangCertServicesBean) UpdateCertV2(request *UpdateCertV2) (*UpdateCertV2Response, error) {
	response := new(UpdateCertV2Response)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *XiZangCertServicesBean) RevokeCert(request *RevokeCert) (*RevokeCertResponse, error) {
	response := new(RevokeCertResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *XiZangCertServicesBean) GenerateCert(request *GenerateCert) (*GenerateCertResponse, error) {
	response := new(GenerateCertResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *XiZangCertServicesBean) GenerateCertZzpt(request *GenerateCertZzpt) (*GenerateCertZzptResponse, error) {
	response := new(GenerateCertZzptResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *XiZangCertServicesBean) GenerateCertLs(request *GenerateCertLs) (*GenerateCertLsResponse, error) {
	response := new(GenerateCertLsResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *XiZangCertServicesBean) ReissueCert(request *ReissueCert) (*ReissueCertResponse, error) {
	response := new(ReissueCertResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *XiZangCertServicesBean) RevokeCertByOper(request *RevokeCertByOper) (*RevokeCertByOperResponse, error) {
	response := new(RevokeCertByOperResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *XiZangCertServicesBean) GetUsbKeyPwd(request *GetUsbKeyPwd) (*GetUsbKeyPwdResponse, error) {
	response := new(GetUsbKeyPwdResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *XiZangCertServicesBean) GenerateEventCert(request *GenerateEventCert) (*GenerateEventCertResponse, error) {
	response := new(GenerateEventCertResponse)
	err := service.client.Call("", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

var timeout = time.Duration(30 * time.Second)

func dialTimeout(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

type SOAPEnvelopeReq struct {
	//XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	XMLName struct{} `xml:"soapenv:Envelope"`
	Ns      string   `xml:"xmlns:soapenv,attr"`

	Header *SOAPHeader
	Body   SOAPBodyReq
}

type SOAPEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Header  *SOAPHeader
	Body    SOAPBody
}

type SOAPHeader struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Header"`

	Items []interface{} `xml:",omitempty"`
}

type SOAPBodyReq struct {
	//XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`
	XMLName struct{} `xml:"soapenv:Body"`
	Ns      string   `xml:"xmlns:soapenv,attr"`

	Fault   *SOAPFault  `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

type SOAPBody struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`

	Fault   *SOAPFault  `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

type SOAPFault struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`

	Code   string `xml:"faultcode,omitempty"`
	String string `xml:"faultstring,omitempty"`
	Actor  string `xml:"faultactor,omitempty"`
	Detail string `xml:"detail,omitempty"`
}

const (
	// Predefined WSS namespaces to be used in
	WssNsWSSE string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	WssNsWSU  string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	WssNsType string = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText"
)

type WSSSecurityHeader struct {
	XMLName   xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ wsse:Security"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`

	MustUnderstand string `xml:"mustUnderstand,attr,omitempty"`

	Token *WSSUsernameToken `xml:",omitempty"`
}

type WSSUsernameToken struct {
	XMLName   xml.Name `xml:"wsse:UsernameToken"`
	XmlNSWsu  string   `xml:"xmlns:wsu,attr"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`

	Id string `xml:"wsu:Id,attr,omitempty"`

	Username *WSSUsername `xml:",omitempty"`
	Password *WSSPassword `xml:",omitempty"`
}

type WSSUsername struct {
	XMLName   xml.Name `xml:"wsse:Username"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`

	Data string `xml:",chardata"`
}

type WSSPassword struct {
	XMLName   xml.Name `xml:"wsse:Password"`
	XmlNSWsse string   `xml:"xmlns:wsse,attr"`
	XmlNSType string   `xml:"Type,attr"`

	Data string `xml:",chardata"`
}

type BasicAuth struct {
	Login    string
	Password string
}

type SOAPClient struct {
	url     string
	tls     bool
	auth    *BasicAuth
	headers []interface{}
}

// **********
// Accepted solution from http://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-golang
// Author: Icza - http://stackoverflow.com/users/1705598/icza

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func randStringBytesMaskImprSrc(n int) string {
	src := rand.NewSource(time.Now().UnixNano())
	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(b)
}

// **********

func NewWSSSecurityHeader(user, pass, mustUnderstand string) *WSSSecurityHeader {
	hdr := &WSSSecurityHeader{XmlNSWsse: WssNsWSSE, MustUnderstand: mustUnderstand}
	hdr.Token = &WSSUsernameToken{XmlNSWsu: WssNsWSU, XmlNSWsse: WssNsWSSE, Id: "UsernameToken-" + randStringBytesMaskImprSrc(9)}
	hdr.Token.Username = &WSSUsername{XmlNSWsse: WssNsWSSE, Data: user}
	hdr.Token.Password = &WSSPassword{XmlNSWsse: WssNsWSSE, XmlNSType: WssNsType, Data: pass}
	return hdr
}

func (b *SOAPBody) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if b.Content == nil {
		return xml.UnmarshalError("Content must be a pointer to a struct")
	}

	var (
		token    xml.Token
		err      error
		consumed bool
	)

Loop:
	for {
		if token, err = d.Token(); err != nil {
			return err
		}

		if token == nil {
			break
		}

		switch se := token.(type) {
		case xml.StartElement:
			if consumed {
				return xml.UnmarshalError("Found multiple elements inside SOAP body; not wrapped-document/literal WS-I compliant")
			} else if se.Name.Space == "http://schemas.xmlsoap.org/soap/envelope/" && se.Name.Local == "Fault" {
				b.Fault = &SOAPFault{}
				b.Content = nil

				err = d.DecodeElement(b.Fault, &se)
				if err != nil {
					return err
				}

				consumed = true
			} else {
				if err = d.DecodeElement(b.Content, &se); err != nil {
					return err
				}

				consumed = true
			}
		case xml.EndElement:
			break Loop
		}
	}

	return nil
}

func (f *SOAPFault) Error() string {
	return f.String
}

func NewSOAPClient(url string, tls bool, auth *BasicAuth) *SOAPClient {
	return &SOAPClient{
		url:  url,
		tls:  tls,
		auth: auth,
	}
}

func (s *SOAPClient) AddHeader(header interface{}) {
	s.headers = append(s.headers, header)
}

func (s *SOAPClient) Call(soapAction string, request, response interface{}) error {
	//envelope := SOAPEnvelope{}
	envelope := SOAPEnvelopeReq{
		Ns: "http://schemas.xmlsoap.org/soap/envelope/",
	}
	envelope.Body.Ns = "http://schemas.xmlsoap.org/soap/envelope/"

	if s.headers != nil && len(s.headers) > 0 {
		soapHeader := &SOAPHeader{Items: make([]interface{}, len(s.headers))}
		copy(soapHeader.Items, s.headers)
		envelope.Header = soapHeader
	}

	envelope.Body.Content = request
	buffer := new(bytes.Buffer)

	encoder := xml.NewEncoder(buffer)
	//encoder.Indent("  ", "    ")

	if err := encoder.Encode(envelope); err != nil {
		return err
	}

	if err := encoder.Flush(); err != nil {
		return err
	}

	log.Println(buffer.String())

	req, err := http.NewRequest("POST", s.url, buffer)
	if err != nil {
		return err
	}
	if s.auth != nil {
		req.SetBasicAuth(s.auth.Login, s.auth.Password)
	}

	req.Header.Add("Content-Type", "text/xml; charset=\"utf-8\"")
	req.Header.Add("SOAPAction", soapAction)

	req.Header.Set("User-Agent", "gowsdl/0.1")
	req.Close = true

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.tls,
		},
		Dial: dialTimeout,
	}

	client := &http.Client{Transport: tr}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	rawbody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if len(rawbody) == 0 {
		log.Println("empty response")
		return nil
	}

	log.Println(string(rawbody))

	respEnvelope := new(SOAPEnvelope)
	respEnvelope.Body = SOAPBody{Content: response}
	err = xml.Unmarshal(rawbody, respEnvelope)
	if err != nil {
		return err
	}

	fault := respEnvelope.Body.Fault
	if fault != nil {
		return fault
	}

	return nil
}
