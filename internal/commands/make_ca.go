package commands

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"math/big"
	"os"
	"time"
)

func makeCaCommand() *cobra.Command {
	var (
		commonName     string
		organization   string
		country        string
		maxPathLen     int
		year           int
		month          int
		keyBits        int
		keyUsage       []int
		keyUsageExt    []int
		certPath       string
		keyPath        string
		parentCertPath string
		parentKeyPath  string
	)
	runCmd := &cobra.Command{
		Use:   "make-ca",
		Short: "Generate a ca certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if (year <= 0) && (month <= 0) {
				return errors.New("invalid date")
			}
			var (
				extKeyUsageList []x509.ExtKeyUsage
				keyUsageResult  x509.KeyUsage
			)
			for _, v := range keyUsageExt {
				extKeyUsageList = append(extKeyUsageList, x509.ExtKeyUsage(v))
			}
			for _, v := range keyUsage {
				keyUsageResult |= x509.KeyUsage(v)
			}
			caTemplate := &x509.Certificate{
				Version:      3,
				SerialNumber: big.NewInt(time.Now().Unix()),
				Subject: pkix.Name{
					CommonName:   commonName,
					Organization: []string{organization},
					Country:      []string{country},
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().AddDate(year, month, 0),
				BasicConstraintsValid: true,
				IsCA:                  true,
				MaxPathLen:            maxPathLen,
				MaxPathLenZero:        maxPathLen == 0,
				KeyUsage:              keyUsageResult,
				ExtKeyUsage:           extKeyUsageList,
			}
			return buildCa(caTemplate, keyBits, certPath, keyPath, parentCertPath, parentKeyPath)
		},
	}
	//CN = GlobalSign Root CA
	//O = GlobalSign nv-sa
	//C = BE
	runCmd.Flags().StringVarP(&commonName, "name", "N", "liuguang root CA", "common name")
	runCmd.Flags().StringVarP(&organization, "organization", "O", "liuguang cert tool", "organization name")
	runCmd.Flags().StringVarP(&country, "country", "C", "CN", "country name")
	runCmd.Flags().IntVar(&maxPathLen, "max-path", -1, "certificate pathLenConstraint")
	runCmd.Flags().IntVarP(&year, "year", "Y", 5, "The validity time of the certificate, calculated by year")
	runCmd.Flags().IntVarP(&month, "month", "M", 0, "The validity time of the certificate, calculated by month")
	runCmd.Flags().IntVar(&keyBits, "key-bits", 2048, "key bits")
	runCmd.Flags().IntSliceVar(&keyUsage, "key-usage", []int{
		int(x509.KeyUsageCertSign),
		int(x509.KeyUsageCRLSign),
	}, "key usage")
	runCmd.Flags().IntSliceVar(&keyUsageExt, "key-usage-ext", []int{}, "extra key usage")
	runCmd.Flags().StringVar(&certPath, "cert-path", "ca.cer", "certificate file output path")
	runCmd.Flags().StringVar(&keyPath, "key-path", "ca_key.pem", "certificate key file output path")
	runCmd.Flags().StringVar(&parentCertPath, "parent-cert-path", "", "parent CA certificate file input path")
	runCmd.Flags().StringVar(&parentKeyPath, "parent-key-path", "", "parent CA certificate key file input path")
	return runCmd
}

func buildCa(caTemplate *x509.Certificate, keyBits int, certPath, keyPath, parentCertPath, parentKeyPath string) error {
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return err
	}
	//??????????????????
	var (
		parentCert                   = caTemplate
		parentKey  crypto.PrivateKey = caPrivateKey
	)
	//??????????????????
	if (parentCertPath != "") && (parentKeyPath != "") {
		parentCertInfo, err := tls.LoadX509KeyPair(parentCertPath, parentKeyPath)
		if err != nil {
			return err
		}
		parentCert, err = x509.ParseCertificate(parentCertInfo.Certificate[0])
		if err != nil {
			return err
		}
		parentKey = parentCertInfo.PrivateKey
	}
	caDer, err := x509.CreateCertificate(rand.Reader, caTemplate, parentCert, caPrivateKey.Public(), parentKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDer)
	if err != nil {
		return err
	}
	keyDer := x509.MarshalPKCS1PrivateKey(caPrivateKey)
	var (
		certBlock = &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		}
		keyBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyDer,
		}
	)
	//
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	if err := pem.Encode(certFile, certBlock); err != nil {
		return err
	}
	if err := pem.Encode(keyFile, keyBlock); err != nil {
		return err
	}
	fmt.Printf("SerialNumber: %x\n", caCert.SerialNumber)
	fmt.Println("start time: " + caTemplate.NotBefore.String())
	fmt.Println("end   time: " + caTemplate.NotAfter.String())
	fmt.Println("build certificate success")
	return nil
}
