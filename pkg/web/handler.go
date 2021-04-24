package web

import (
	"encoding/base64"
	"encoding/json"
	"github.com/jijiechen/qcloud-ssl-secret/pkg/qcloud"
	"io/ioutil"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/klog"
	"net/http"
)

var (
	runtimeScheme = runtime.NewScheme()
	codeFactory   = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codeFactory.UniversalDeserializer()
)

const (
	CertIdAnnotationKey = "ssl.cloud.tencent.com/certificate-id"
)

type WebhookHandler struct {
	Server *http.Server
	QCloudParams *QCloudIntegrationParams
}

func (handler *WebhookHandler) Mutate(writer http.ResponseWriter, request *http.Request) {
	var bodyBytes []byte
	if request.Body != nil {
		if data, err := ioutil.ReadAll(request.Body); err == nil {
			bodyBytes = data
		}
	}

	if len(bodyBytes) == 0 {
		klog.Warning("Bad request detected: empty request body")
		http.Error(writer, "Empty request", http.StatusBadRequest)
		return
	}

	contentType := request.Header.Get("Content-Type")
	if contentType != "application/json" {
		klog.Warning("Bad request detected: Content-Type is %s, application/json expected", contentType)
		http.Error(writer, "Invalid Content-Type, application/json expected", http.StatusBadRequest)
		return
	}

	requestedAdmissionReview := admissionv1.AdmissionReview{}
	if _, _, err := deserializer.Decode(bodyBytes, nil, &requestedAdmissionReview); err != nil {
		klog.Warning("Bad request detected: failed to decode request body: %v", err)
		http.Error(writer, "Invalid request", http.StatusBadRequest)
		return
	}


	reviewedAdmission := admissionv1.AdmissionReview{}
	reviewedAdmission.APIVersion = requestedAdmissionReview.APIVersion
	reviewedAdmission.Kind = requestedAdmissionReview.Kind
	reviewedAdmission.Response = handler.mutate(&requestedAdmissionReview)
	if requestedAdmissionReview.Request != nil {
		reviewedAdmission.Response.UID = requestedAdmissionReview.Request.UID
	}

	respBytes, err := json.Marshal(reviewedAdmission)
	if err != nil {
		klog.Warning("Failed to encode response: %v", err)
		http.Error(writer, "Unknown error", http.StatusInternalServerError)
		return
	}

	klog.Info("Sending response...")
	if _, err := writer.Write(respBytes); err != nil {
		klog.Errorf("Failed to write response: %v", err)
		http.Error(writer, "Unknown error", http.StatusInternalServerError)
	}
}

func (handler *WebhookHandler) mutate(admissionReview *admissionv1.AdmissionReview) *admissionv1.AdmissionResponse {
	allowed := &admissionv1.AdmissionResponse{
		Allowed: true,
	}
	req := admissionReview.Request
	klog.Infof("Reviewing resource: Kind=%handler, Namespace=%handler Name=%handler UID=%handler", req.Kind.Kind, req.Namespace, req.Name, req.UID)

	if req.Kind.Kind != "Secret" {
		return allowed
	}

	var secret corev1.Secret
	if err := json.Unmarshal(req.Object.Raw, &secret); err != nil {
		klog.Warning("Failed to decode raw object: %v", err)
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Code:    http.StatusBadRequest,
				Message: err.Error(),
			},
		}
	}

	objectMeta := &secret.ObjectMeta
	certId, annotated := objectMeta.GetAnnotations()[CertIdAnnotationKey]
	if !annotated {
		return allowed
	}

	certBytes, keyBytes, caBytes, err := qcloud.DownloadCertificate(&certId, handler.QCloudParams.SecretId, handler.QCloudParams.SecretKey)
	if err != nil {
		klog.Warning("Failed to download certificate %s: %v", certId, err)
	}

	patches := generatePatch(certBytes, keyBytes, caBytes)
	patchesBytes, err := json.Marshal(patches)
	if err != nil {
		klog.Warning("Failed to marshal patch operations. error: %v", err)
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Code:    http.StatusInternalServerError,
				Message: err.Error(),
			},
		}
	}

	return &admissionv1.AdmissionResponse{
		Allowed: true,
		Patch:   patchesBytes,
		PatchType: func() *admissionv1.PatchType {
			pt := admissionv1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

func generatePatch(certBytes []byte, keyBytes []byte, caBytes []byte) (patch []ResourcePatchOperation) {
	// change type? type: kubernetes.io/tls
	certStr := base64.StdEncoding.EncodeToString(certBytes)
	keyStr := base64.StdEncoding.EncodeToString(keyBytes)

	patch = append(patch, ResourcePatchOperation{
		Op:    "add",
		Path:  "/spec/data/tls.crt",
		Value: certStr,
	})
	patch = append(patch, ResourcePatchOperation{
		Op:    "add",
		Path:  "/spec/data/tls.key",
		Value: keyStr,
	})

	if caBytes != nil {
		caStr := base64.StdEncoding.EncodeToString(caBytes)
		patch = append(patch, ResourcePatchOperation{
			Op:    "add",
			Path:  "/spec/data/ca.crt",
			Value: caStr,
		})
	}
	return
}
