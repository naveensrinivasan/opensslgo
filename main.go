package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/davecgh/go-spew/spew"
)

func main() {
	publicKey := `-----BEGIN CERTIFICATE-----
MIIDrDCCAzOgAwIBAgIUCO7lGezV94Ej5zBLWdcAVgjKnj0wCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjIwODE1MTM0NjMwWhcNMjIwODE1MTM1NjMwWjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEsg4SuAYOsbxQzSkcteWrirKq7mB/Z9zAFqe6
1hkPoVGpTJ7p4dXNcW4oZh0N7b6mcUj6h8NDfI1yXEoIU4cZUqOCAlIwggJOMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUHX2k
rxOMcMqSSBaNLX+g9Avu8EcwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wZgYDVR0RAQH/BFwwWoZYaHR0cHM6Ly9naXRodWIuY29tL3NpZ3N0b3JlL3Jl
a29yLy5naXRodWIvd29ya2Zsb3dzL3Njb3JlY2FyZF9hY3Rpb24ueW1sQHJlZnMv
aGVhZHMvbWFpbjA5BgorBgEEAYO/MAEBBCtodHRwczovL3Rva2VuLmFjdGlvbnMu
Z2l0aHVidXNlcmNvbnRlbnQuY29tMBIGCisGAQQBg78wAQIEBHB1c2gwNgYKKwYB
BAGDvzABAwQoY2U0M2FlYjlhYjJlMjc2NDZiNjA2ZDI4ODE0MDkyMTIwYTg4NTg3
ZTAuBgorBgEEAYO/MAEEBCBTY29yZWNhcmRzIHN1cHBseS1jaGFpbiBzZWN1cml0
eTAcBgorBgEEAYO/MAEFBA5zaWdzdG9yZS9yZWtvcjAdBgorBgEEAYO/MAEGBA9y
ZWZzL2hlYWRzL21haW4wgYoGCisGAQQB1nkCBAIEfAR6AHgAdgAIYJLwKFL/aEXR
0WsnhJxFZxisFj3DONJt5rwiBjZvcgAAAYKhwYWyAAAEAwBHMEUCIAceDgg7renN
AfHF083EJcq7OssYx/woCe0u4gbNC5chAiEAlOz9tC2H72D2PYEgu6GjoYjT9YOw
SSHje/xMIb0G9bQwCgYIKoZIzj0EAwMDZwAwZAIwWH2cKm9btHzLXJGJuXzMfbI8
75MeL2IwZo4SUgCTeF4Ojsd3ue4GQ0cHH9VreLmPAjBi8TytobL74XKTRz9rFMQi
QkDk2FLnbks1njisGa4L8iJUaNuat8XQGGB9QD5MUcQ=
-----END CERTIFICATE-----
`
	/*
		bcallaway@bcallaway01:~/git/sigstore/rekor$ ./rekor-cli get --log-index 3184738 --format json|jq -r .Body.HashedRekordObj.signature.publicKey.content|base64 -d|openssl x509 -print -noout -text
		Certificate:
		    Data:
		        Version: 3 (0x2)
		        Serial Number:
		            08:ee:e5:19:ec:d5:f7:81:23:e7:30:4b:59:d7:00:56:08:ca:9e:3d
		        Signature Algorithm: ecdsa-with-SHA384
		        Issuer: O = sigstore.dev, CN = sigstore-intermediate
		        Validity
		            Not Before: Aug 15 13:46:30 2022 GMT
		            Not After : Aug 15 13:56:30 2022 GMT
		        Subject:
		        Subject Public Key Info:
		            Public Key Algorithm: id-ecPublicKey
		                Public-Key: (256 bit)
		                pub:
		                    04:b2:0e:12:b8:06:0e:b1:bc:50:cd:29:1c:b5:e5:
		                    ab:8a:b2:aa:ee:60:7f:67:dc:c0:16:a7:ba:d6:19:
		                    0f:a1:51:a9:4c:9e:e9:e1:d5:cd:71:6e:28:66:1d:
		                    0d:ed:be:a6:71:48:fa:87:c3:43:7c:8d:72:5c:4a:
		                    08:53:87:19:52
		                ASN1 OID: prime256v1
		                NIST CURVE: P-256
		        X509v3 extensions:
		            X509v3 Key Usage: critical
		                Digital Signature
		            X509v3 Extended Key Usage:
		                Code Signing
		            X509v3 Subject Key Identifier:
		                1D:7D:A4:AF:13:8C:70:CA:92:48:16:8D:2D:7F:A0:F4:0B:EE:F0:47
		            X509v3 Authority Key Identifier:
		                DF:D3:E9:CF:56:24:11:96:F9:A8:D8:E9:28:55:A2:C6:2E:18:64:3F
		            X509v3 Subject Alternative Name: critical
		                URI:https://github.com/sigstore/rekor/.github/workflows/scorecard_action.yml@refs/heads/main
		            1.3.6.1.4.1.57264.1.1:
		                https://token.actions.githubusercontent.com
		            1.3.6.1.4.1.57264.1.2:
		                push
		            1.3.6.1.4.1.57264.1.3:
		                ce43aeb9ab2e27646b606d28814092120a88587e
		            1.3.6.1.4.1.57264.1.4:
		                Scorecards supply-chain security
		            1.3.6.1.4.1.57264.1.5:
		                sigstore/rekor
		            1.3.6.1.4.1.57264.1.6:
		                refs/heads/main
		            CT Precertificate SCTs:
		                Signed Certificate Timestamp:
		                    Version   : v1 (0x0)
		                    Log ID    : 08:60:92:F0:28:52:FF:68:45:D1:D1:6B:27:84:9C:45:
		                                67:18:AC:16:3D:C3:38:D2:6D:E6:BC:22:06:36:6F:72
		                    Timestamp : Aug 15 13:46:30.706 2022 GMT
		                    Extensions: none
		                    Signature : ecdsa-with-SHA256
		                                30:45:02:20:07:1E:0E:08:3B:AD:E9:CD:01:F1:C5:D3:
		                                CD:C4:25:CA:BB:3A:CB:18:C7:FC:28:09:ED:2E:E2:06:
		                                CD:0B:97:21:02:21:00:94:EC:FD:B4:2D:87:EF:60:F6:
		                                3D:81:20:BB:A1:A3:A1:88:D3:F5:83:B0:49:21:E3:7B:
		                                FC:4C:21:BD:06:F5:B4
		    Signature Algorithm: ecdsa-with-SHA384
		    Signature Value:
		        30:64:02:30:58:7d:9c:2a:6f:5b:b4:7c:cb:5c:91:89:b9:7c:
		        cc:7d:b2:3c:ef:93:1e:2f:62:30:66:8e:12:52:00:93:78:5e:
		        0e:8e:c7:77:b9:ee:06:43:47:07:1f:d5:6b:78:b9:8f:02:30:
		        62:f1:3c:ad:a1:b2:fb:e1:72:93:47:3f:6b:14:c4:22:42:40:
		        e4:d8:52:e7:6e:4b:35:9e:38:ac:19:ae:0b:f2:22:54:68:db:
		        9a:b7:c5:d0:18:60:7d:40:3e:4c:51:c4
	*/
	// cat public.key | openssl x509  -noout -text

	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	// print the
	fmt.Println("Version:", cert.Version)
	fmt.Println("Version:", cert.Version)
	fmt.Printf("Serial Number:%x\n", cert.SerialNumber)
	fmt.Println("Signature Algorithm:", cert.SignatureAlgorithm.String())
	fmt.Println("Issuer:", cert.Issuer.Organization[0], cert.Issuer.CommonName)
	fmt.Println()
	fmt.Println("Validity:")
	fmt.Println(cert.NotBefore)
	fmt.Println(cert.NotAfter)
	fmt.Println(cert.Subject)
	fmt.Println("X509v3 extensions:")
	spew.Dump(cert.Extensions)
	fmt.Println("Signature Algorithm:", cert.SignatureAlgorithm)
	fmt.Println(" Signature Value:")
	spew.Dump(cert.Signature)
}
