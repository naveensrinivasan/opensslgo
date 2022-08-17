package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

type CertExtension struct {
	ID    *string `json:"id,omitempty"`
	Value *string `json:"value,omitempty"`
}
type Certificate struct {
	Version            *int             `json:"version,omitempty"`
	SerialNumber       *string          `json:"serial_number,omitempty"`
	SignatureAlgorithm *string          `json:"signature_algorithm,omitempty"`
	IssuerOrganization *string          `json:"issuer_organization,omitempty"`
	IssuerCommonName   *string          `json:"issuer_common_name,omitempty"`
	ValidityNotBefore  *time.Time       `json:"validity_not_before,omitempty"`
	ValidityNotAfter   *time.Time       `json:"validity_not_after,omitempty"`
	Extensions         *[]CertExtension `json:"extensions,omitempty"`
}

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

	certificate, err := parseX509(publicKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	jsons, _ := json.Marshal(certificate)
	fmt.Println(string(jsons))
}

func parseX509(publicKey string) (Certificate, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return Certificate{}, fmt.Errorf("failed to parse PEM block containing the key")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Certificate{}, err
	}
	serialNumber := cert.SerialNumber.String()
	signatureAlgorithm := cert.SignatureAlgorithm.String()
	var extension []CertExtension
	validCerts := map[string]bool{
		"2.5.29.17":             true,
		"1.3.6.1.4.1.57264.1.1": true,
		"1.3.6.1.4.1.57264.1.2": true,
		"1.3.6.1.4.1.57264.1.3": true,
		"1.3.6.1.4.1.57264.1.4": true,
		"1.3.6.1.4.1.57264.1.5": true,
		"1.3.6.1.4.1.57264.1.6": true,
	}

	for _, e := range cert.Extensions {
		if _, ok := validCerts[e.Id.String()]; !ok {
			continue
		}
		id := e.Id.String()
		value := string(e.Value)
		extension = append(extension, CertExtension{
			ID:    &id,
			Value: &value,
		})
	}
	certificate := Certificate{
		Version:            &cert.Version,
		SerialNumber:       &serialNumber,
		SignatureAlgorithm: &signatureAlgorithm,
		IssuerOrganization: &cert.Issuer.Organization[0],
		IssuerCommonName:   &cert.Issuer.CommonName,
		ValidityNotBefore:  &cert.NotBefore,
		ValidityNotAfter:   &cert.NotAfter,
		Extensions:         &extension,
	}
	return certificate, nil
}
