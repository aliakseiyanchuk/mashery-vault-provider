package mashery

import (
	"github.com/aliakseiyanchuk/mashery-v3-go-client/v3client"
)

const (
	secretAreaIdField        = "area_id"
	secretAreaNidField       = "area_nid"
	secretApiKeField         = "api_key"
	secretKeySecretField     = "secret"
	secretSignedSecretField  = "sig"
	secretUsernameField      = "username"
	secretPasswordField      = "password"
	secretQpsField           = "qps"
	secretLeaseDurationField = "lease_duration"
	secretAccessToken        = "access_token"

	secretInternalSiteStoragePath = "siteStoragePath"
	secretInternalRefreshToken    = "refresh_token"
	// Token expiry time in Epoch seconds
	secretInternalTokenExpiryTime = "token_expiry_time"
)

type AuthRec struct {
	AreaId        string `json:"area_id"`
	AreaNid       int    `json:"area_nid"`
	ApiKey        string `json:"api_key"`
	KeySecret     string `json:"secret"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	MaxQPS        int    `json:"qps"`
	LeaseDuration int    `json:"duration"`
}

func (ar AuthRec) asV3Credentials() v3client.MasheryV3Credentials {
	return v3client.MasheryV3Credentials{
		AreaId:   ar.AreaId,
		ApiKey:   ar.ApiKey,
		Secret:   ar.KeySecret,
		Username: ar.Username,
		Password: ar.Password,
	}
}
