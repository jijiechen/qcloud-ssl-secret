package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/jijiechen/qcloud-ssl-secret/pkg/web"
	"k8s.io/klog"
)

func main() {
	var params web.QCloudIntegrationParams

	flag.StringVar(&params.SslServiceBaseUrl, "service-url", "ssl.tencentcloudapi.com", "QCloud SSL Service API Base URL.")
	flag.StringVar(&params.SecretId, "secret-id", "", "QCloud access key secret id.")
	flag.StringVar(&params.SecretKey, "secret-key", "", "QCloud access key secret key.")
	flag.Parse()

	if len(params.SslServiceBaseUrl) == 0 || len(params.SecretId) == 0 || len(params.SecretKey) == 0 {
		fmt.Printf("Please specify values for the required arguments:\n")
		flag.PrintDefaults()
		return
	}

	cert, err := tls.LoadX509KeyPair("/etc/qcloud-ssl-secret/tls.crt", "/etc/qcloud-ssl-secret/tls.key")
	//cert, err := tls.LoadX509KeyPair("./tls.crt", "./tls.key")
	if err != nil {
		klog.Errorf("Failed to load server certificate and key pair: %v", err)
		os.Exit(127)
	}

	webhookHandler := web.WebhookHandler{
		Server: &http.Server{
			Addr: fmt.Sprintf(":%d", 8080),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		},
		QCloudParams: &params,
	}

	httpHandler := http.NewServeMux()
	httpHandler.HandleFunc("/mutate", webhookHandler.Mutate)
	webhookHandler.Server.Handler = httpHandler

	go func() {
		if err := webhookHandler.Server.ListenAndServeTLS("", ""); err != nil {
			klog.Errorf("Failed to listen and serve webhook: %v", err)
			os.Exit(1)
		}
	}()

	klog.Info("Server started")

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	klog.Infof("Termination signal received, shutting down...")
	if err := webhookHandler.Server.Shutdown(context.Background()); err != nil {
		klog.Errorf("Error shutting down: %v", err)
	}
}
