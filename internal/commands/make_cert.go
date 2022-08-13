package commands

import (
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
	"net"
	"os"
	"time"
)

func makeCertCommand() *cobra.Command {
	var (
		commonName   string
		organization string
		country      string
		year         int
		month        int
		keyBits      int
		keyUsage     []int
		keyUsageExt  []int
		domainList   []string
		ipList       []string
		certPath     string
		keyPath      string
		caCertPath   string
		caKeyPath    string
	)
	runCmd := &cobra.Command{
		Use:   "make-cert",
		Short: "Generate a ssl certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			if (year <= 0) && (month <= 0) {
				return errors.New("invalid date")
			}
			var (
				extKeyUsageList []x509.ExtKeyUsage
				keyUsageResult  x509.KeyUsage
				ipAddrList      []net.IP
			)
			for _, v := range keyUsageExt {
				extKeyUsageList = append(extKeyUsageList, x509.ExtKeyUsage(v))
			}
			for _, v := range keyUsage {
				keyUsageResult |= x509.KeyUsage(v)
			}
			for _, v := range ipList {
				ipAddrList = append(ipAddrList, net.ParseIP(v))
			}
			caTemplate := &x509.Certificate{
				Version:      3,
				SerialNumber: big.NewInt(time.Now().Unix()),
				Subject: pkix.Name{
					CommonName:   commonName,
					Organization: []string{organization},
					Country:      []string{country},
				},
				NotBefore:   time.Now(),
				NotAfter:    time.Now().AddDate(year, month, 0),
				KeyUsage:    keyUsageResult,
				ExtKeyUsage: extKeyUsageList,
				DNSNames:    domainList,
				IPAddresses: ipAddrList,
			}
			return buildCert(caTemplate, keyBits, certPath, keyPath, caCertPath, caKeyPath)
		},
	}
	//CN = GlobalSign Root CA
	//O = GlobalSign nv-sa
	//C = BE
	runCmd.Flags().StringVarP(&commonName, "name", "N", "liuguang ssl cert", "common name")
	runCmd.Flags().StringVarP(&organization, "organization", "O", "liuguang cert tool", "organization name")
	runCmd.Flags().StringVarP(&country, "country", "C", "CN", "country name")
	runCmd.Flags().IntVarP(&year, "year", "Y", 2, "The validity time of the certificate, calculated by year")
	runCmd.Flags().IntVarP(&month, "month", "M", 0, "The validity time of the certificate, calculated by month")
	runCmd.Flags().IntVar(&keyBits, "key-bits", 2048, "key bits")
	runCmd.Flags().IntSliceVar(&keyUsage, "key-usage", []int{
		int(x509.KeyUsageDigitalSignature),
		int(x509.KeyUsageKeyEncipherment),
	}, "key usage")
	runCmd.Flags().IntSliceVar(&keyUsageExt, "key-usage-ext", []int{
		int(x509.ExtKeyUsageServerAuth),
		int(x509.ExtKeyUsageClientAuth),
	}, "extra key usage")
	runCmd.Flags().StringSliceVar(&domainList, "domain", []string{}, "domainList list")
	runCmd.Flags().StringSliceVar(&ipList, "ip", []string{}, "IP list")
	runCmd.Flags().StringVar(&certPath, "cert-path", "ssl.cer", "certificate file output path")
	runCmd.Flags().StringVar(&keyPath, "key-path", "ssl_key.pem", "certificate key file output path")
	runCmd.Flags().StringVar(&caCertPath, "ca-cert-path", "", "CA certificate file input path")
	runCmd.Flags().StringVar(&caKeyPath, "ca-key-path", "", "CA certificate key file input path")
	runCmd.MarkFlagRequired("ca-cert-path")
	runCmd.MarkFlagRequired("ca-key-path")
	return runCmd
}

func buildCert(caTemplate *x509.Certificate, keyBits int, certPath, keyPath, parentCertPath, parentKeyPath string) error {
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return err
	}
	//加载上级证书
	parentCertInfo, err := tls.LoadX509KeyPair(parentCertPath, parentKeyPath)
	if err != nil {
		return err
	}
	parentCert, err := x509.ParseCertificate(parentCertInfo.Certificate[0])
	if err != nil {
		return err
	}
	parentKey := parentCertInfo.PrivateKey
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
