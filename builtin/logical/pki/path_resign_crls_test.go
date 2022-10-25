package pki

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestResignCrls(t *testing.T) {
	pem1 := "-----BEGIN X509 CRL-----\nMIIBvjCBpwIBATANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDExByb290LWV4YW1w\nbGUuY29tFw0yMjEwMjYyMTI5MzlaFw0yMjEwMjkyMTI5MzlaMCcwJQIUSnVf8wsd\nHjOt9drCYFhWxS9QqGoXDTIyMTAyNjIxMjkzOVqgLzAtMB8GA1UdIwQYMBaAFHki\nZ0XDUQVSajNRGXrg66OaIFlYMAoGA1UdFAQDAgEDMA0GCSqGSIb3DQEBCwUAA4IB\nAQBGIdtqTwemnLZF5AoP+jzvKZ26S3y7qvRIzd7f4A0EawzYmWXSXfwqo4TQ4DG3\nnvT+AaA1zCCOlH/1U+ufN9gSSN0j9ax58brSYMnMskMCqhLKIp0qnvS4jr/gopmF\nv8grbvLHEqNYTu1T7umMLdNQUsWT3Qc+EIjfoKj8xD2FHsZwJ+EMbytwl8Unipjr\nhz4rmcES/65vavfdFpOI6YXfi+UAaHBdkTqmHgg4BdpuXfYtlf+iotFSOkygD5fl\n0D+RVFW9uJv2WfbQ7kRt1X/VcFk/onw0AQqxZRVUzvjoMw+EMcxSq3UKOlXcWDxm\nEFz9rFQQ66L388EP8RD7Dh3X\n-----END X509 CRL-----"
	pem2 := "-----BEGIN X509 CRL-----\nMIIBvjCBpwIBATANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDExByb290LWV4YW1w\nbGUuY29tFw0yMjEwMjYyMTI5MzlaFw0yMjEwMjkyMTI5MzlaMCcwJQIUPPlHdKzc\nnMljHN3vDcqQkyRWWxQXDTIyMTAyNjIxMjkzOVqgLzAtMB8GA1UdIwQYMBaAFMbF\nfDMrtoqudv3bp1YLbjNOqY/YMAoGA1UdFAQDAgEDMA0GCSqGSIb3DQEBCwUAA4IB\nAQBYBeMjyffefICs2nNy6Fs0SsKyWCk1IS5tu49hEOnxck9UTllu7nktVLis5+5p\nM51FDhFp7L+Su67nMLYgqs6+9CV2QiacGul6kW/ubVIGu5uaNo3duYUrF6tLre/m\nkftUo4yzSF3buB4xu+5lZktgLvh/icofzoa2QwMJNKdApqVxDXbr8HQtM6eep4i1\n+KbFrficULHqDC5XBIT140NzzPsIYWFjtjSB/bTTxScNOma776CdQK4I+CzPF6++\nhxiyNaN7qqkrP+4w9XWAg7CorakPfY00oDcnCiqF70qdZm8VcvpUpf2HqdSGQrwI\nkw0UTVewb0wSok+H4TCWep2L\n-----END X509 CRL-----"

	crl1, err := decodePemCrl(pem1)
	require.NoError(t, err, "failed decoding pem 1 CRL")
	crl2, err := decodePemCrl(pem2)
	require.NoError(t, err, "failed decoding pem 2 CRL")

	pem1Serial := extractSerialsFromCrl(crl1)[0]
	pem2Serial := extractSerialsFromCrl(crl2)[0]

	b, s := createBackendWithStorage(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   s,
		Data: map[string]interface{}{
			"common_name": "test.com",
		},
		MountPoint: "pki/",
	})
	requireSuccessNonNilResponse(t, resp, err)
	pemCaCert := resp.Data["certificate"].(string)
	caCert := parseCert(t, pemCaCert)

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issuer/default/resign-crls",
		Storage:   s,
		Data: map[string]interface{}{
			"crl_number":  "2",
			"next_update": "1h",
			"format":      "pem",
			"crls":        []string{pem1, pem2},
		},
		MountPoint: "pki/",
	})
	requireSuccessNonNilResponse(t, resp, err)
	requireFieldsSetInResp(t, resp, "crl")
	pemCrl := resp.Data["crl"].(string)
	combinedCrl, err := decodePemCrl(pemCrl)
	require.NoError(t, err, "failed decoding combined CRL")
	serials := extractSerialsFromCrl(combinedCrl)

	require.Contains(t, serials, pem1Serial)
	require.Contains(t, serials, pem2Serial)
	require.Equal(t, 2, len(serials), "serials contained more serials than expected")

	require.Equal(t, big.NewInt(int64(2)), combinedCrl.Number)
	require.Equal(t, combinedCrl.ThisUpdate.Add(1*time.Hour), combinedCrl.NextUpdate)

	err = combinedCrl.CheckSignatureFrom(caCert)
	require.NoError(t, err, "failed signature check of CRL")
}

func TestResignCrlsDelta(t *testing.T) {
	pem1 := "-----BEGIN X509 CRL-----\nMIIBvjCBpwIBATANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDExByb290LWV4YW1w\nbGUuY29tFw0yMjEwMjYyMTI5MzlaFw0yMjEwMjkyMTI5MzlaMCcwJQIUSnVf8wsd\nHjOt9drCYFhWxS9QqGoXDTIyMTAyNjIxMjkzOVqgLzAtMB8GA1UdIwQYMBaAFHki\nZ0XDUQVSajNRGXrg66OaIFlYMAoGA1UdFAQDAgEDMA0GCSqGSIb3DQEBCwUAA4IB\nAQBGIdtqTwemnLZF5AoP+jzvKZ26S3y7qvRIzd7f4A0EawzYmWXSXfwqo4TQ4DG3\nnvT+AaA1zCCOlH/1U+ufN9gSSN0j9ax58brSYMnMskMCqhLKIp0qnvS4jr/gopmF\nv8grbvLHEqNYTu1T7umMLdNQUsWT3Qc+EIjfoKj8xD2FHsZwJ+EMbytwl8Unipjr\nhz4rmcES/65vavfdFpOI6YXfi+UAaHBdkTqmHgg4BdpuXfYtlf+iotFSOkygD5fl\n0D+RVFW9uJv2WfbQ7kRt1X/VcFk/onw0AQqxZRVUzvjoMw+EMcxSq3UKOlXcWDxm\nEFz9rFQQ66L388EP8RD7Dh3X\n-----END X509 CRL-----"
	pem2 := "-----BEGIN X509 CRL-----\nMIIBvjCBpwIBATANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDExByb290LWV4YW1w\nbGUuY29tFw0yMjEwMjYyMTI5MzlaFw0yMjEwMjkyMTI5MzlaMCcwJQIUPPlHdKzc\nnMljHN3vDcqQkyRWWxQXDTIyMTAyNjIxMjkzOVqgLzAtMB8GA1UdIwQYMBaAFMbF\nfDMrtoqudv3bp1YLbjNOqY/YMAoGA1UdFAQDAgEDMA0GCSqGSIb3DQEBCwUAA4IB\nAQBYBeMjyffefICs2nNy6Fs0SsKyWCk1IS5tu49hEOnxck9UTllu7nktVLis5+5p\nM51FDhFp7L+Su67nMLYgqs6+9CV2QiacGul6kW/ubVIGu5uaNo3duYUrF6tLre/m\nkftUo4yzSF3buB4xu+5lZktgLvh/icofzoa2QwMJNKdApqVxDXbr8HQtM6eep4i1\n+KbFrficULHqDC5XBIT140NzzPsIYWFjtjSB/bTTxScNOma776CdQK4I+CzPF6++\nhxiyNaN7qqkrP+4w9XWAg7CorakPfY00oDcnCiqF70qdZm8VcvpUpf2HqdSGQrwI\nkw0UTVewb0wSok+H4TCWep2L\n-----END X509 CRL-----"

	crl1, err := decodePemCrl(pem1)
	require.NoError(t, err, "failed decoding pem 1 CRL")
	crl2, err := decodePemCrl(pem2)
	require.NoError(t, err, "failed decoding pem 2 CRL")

	pem1Serial := extractSerialsFromCrl(crl1)[0]
	pem2Serial := extractSerialsFromCrl(crl2)[0]

	b, s := createBackendWithStorage(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   s,
		Data: map[string]interface{}{
			"common_name": "test.com",
		},
		MountPoint: "pki/",
	})
	requireSuccessNonNilResponse(t, resp, err)
	pemCaCert := resp.Data["certificate"].(string)
	caCert := parseCert(t, pemCaCert)

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issuer/default/resign-crls",
		Storage:   s,
		Data: map[string]interface{}{
			"crl_number":       "5",
			"delta_crl_number": "4",
			"next_update":      "12h",
			"format":           "pem",
			"crls":             []string{pem1, pem2},
		},
		MountPoint: "pki/",
	})
	requireSuccessNonNilResponse(t, resp, err)
	requireFieldsSetInResp(t, resp, "crl")
	pemCrl := resp.Data["crl"].(string)
	combinedCrl, err := decodePemCrl(pemCrl)
	require.NoError(t, err, "failed decoding combined CRL")
	serials := extractSerialsFromCrl(combinedCrl)

	require.Contains(t, serials, pem1Serial)
	require.Contains(t, serials, pem2Serial)
	require.Equal(t, 2, len(serials), "serials contained more serials than expected")

	require.Equal(t, big.NewInt(int64(5)), combinedCrl.Number)
	require.Equal(t, combinedCrl.ThisUpdate.Add(12*time.Hour), combinedCrl.NextUpdate)

	extensions := combinedCrl.Extensions
	requireExtensionOid(t, []int{2, 5, 29, 27}, extensions) // Delta CRL Extension
	requireExtensionOid(t, []int{2, 5, 29, 20}, extensions) // CRL Number Extension
	requireExtensionOid(t, []int{2, 5, 29, 35}, extensions) // akidOid
	require.Equal(t, 3, len(extensions))

	err = combinedCrl.CheckSignatureFrom(caCert)
	require.NoError(t, err, "failed signature check of CRL")
}

func requireExtensionOid(t *testing.T, identifier asn1.ObjectIdentifier, extensions []pkix.Extension, msgAndArgs ...interface{}) {
	found := false
	var oidsInExtensions []string
	for _, extension := range extensions {
		oidsInExtensions = append(oidsInExtensions, extension.Id.String())
		if extension.Id.Equal(identifier) {
			found = true
			break
		}
	}

	if !found {
		msg := fmt.Sprintf("Failed to find matching asn oid %s out of %v", identifier.String(), oidsInExtensions)
		require.Fail(t, msg, msgAndArgs)
	}
}

func extractSerialsFromCrl(crl *x509.RevocationList) []string {
	var serials []string
	for _, revokedCert := range crl.RevokedCertificates {
		serials = append(serials, serialFromBigInt(revokedCert.SerialNumber))
	}
	return serials
}
