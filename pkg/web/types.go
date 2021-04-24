package web



type QCloudIntegrationParams struct {
	SslServiceBaseUrl string
	SecretId string
	SecretKey string
}

type ResourcePatchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}