package qcloud

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	sslsdk "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
	"io/ioutil"
	"strings"
)

func DownloadCertificate(certId *string, secretId string, secretKey string) (certBytes []byte, keyBytes []byte, err error) {
	reqProfile := profile.NewClientProfile()
	reqProfile.HttpProfile.ReqMethod = "GET"

	credentials := common.Credential{
		SecretId: secretId,
		SecretKey: secretKey,
	}
	client, err := sslsdk.NewClient(&credentials, "", reqProfile)
	if err != nil{
		return nil,nil, err
	}

	request := sslsdk.NewDownloadCertificateRequest()
	request.CertificateId = certId

	certificate, err := client.DownloadCertificate(request)
	if err != nil {
		return nil, nil, err
	}

	zipContent := certificate.Response.Content
	zipBytes, err := base64.StdEncoding.DecodeString(*zipContent)

	zipReader, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return nil, nil,  err
	}

	for _, zipFile := range zipReader.File {
		fileName := zipFile.Name
		if len(fileName) < 4 || strings.Contains(fileName, "/")  ||
			(!strings.HasSuffix(fileName, ".pem") && !strings.HasSuffix(fileName, ".key")) {
			continue
		}

		unzippedFileBytes, err := readZipFile(zipFile)
		if err != nil {
			continue
		}

		ext := string(fileName[len(fileName)-4:])
		switch ext {
		case ".pem":
			certBytes = unzippedFileBytes
		case ".key":
			keyBytes = unzippedFileBytes
		}
	}

	return
}

func readZipFile(file *zip.File) ([]byte, error) {
	f, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioutil.ReadAll(f)
}

