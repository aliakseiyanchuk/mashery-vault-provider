package mashery

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"time"
)

const (
	pathV2CredentialsHelpSyn  = "Retrieves Mashery V2 API authorization signature"
	pathV2CredentialsHelpDesc = `
Mashery V2 authentication token comprises api key, Mashery are numeric id, and time-salted signature of the secret. 
This makes this lease non-renewable and non-revocable. The maximum technical validity of the signature is capped 
at 5 minutes since the moment it was issued. Applications using Mashery V2 API are recommended to refresh this 
token very minute.
`

	secretMasheryV2Access = "v2_access"
)

func pathV2Credentials(b *AuthPlugin) *framework.Path {
	return &framework.Path{
		Pattern: "auth/" + framework.GenericNameWithAtRegex(credentialsName) + "/v2",
		Fields: map[string]*framework.FieldSchema{
			credentialsName: {
				Type:        framework.TypeString,
				Description: "Mashery area logical name",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadV2Credentials,
				Summary:  "Retrieve V2 signature",
			},
		},

		ExistenceCheck: b.siteExistenceCheck,

		HelpSynopsis:    pathV2CredentialsHelpSyn,
		HelpDescription: pathV2CredentialsHelpDesc,
	}
}

func v2AccessSecret(b *AuthPlugin) *framework.Secret {
	return &framework.Secret{
		Type: secretMasheryV2Access,
		Fields: map[string]*framework.FieldSchema{
			secretAreaNidField: {
				Type:        framework.TypeInt,
				Description: "Mashery Area Numeric Id",
			},
			secretApiKeField: {
				Type:        framework.TypeString,
				Description: "Mashery V2 API Key",
			},
			secretSignedSecretField: {
				Type:        framework.TypeString,
				Description: "Salted signed secret",
			},
			secretQpsField: {
				Type:        framework.TypeInt,
				Description: "Maximum QPS this key can achieve",
			},
		},
		DefaultDuration: time.Minute,
		Revoke:          b.noopRenewRevoke,
	}
}

func suppliesKeyAndSecret(v3Rec *AuthRec) bool {
	return len(v3Rec.ApiKey) > 0 && len(v3Rec.KeySecret) > 0
}

func (b *AuthPlugin) pathReadV2Credentials(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if entry, err := req.Storage.Get(ctx, storagePathForMasheryArea(d)); err != nil {
		return nil, errwrap.Wrapf("cannot read site credentials: {{err}", err)
	} else {
		v3Rec := AuthRec{}
		if err := entry.DecodeJSON(&v3Rec); err != nil {
			return nil, errwrap.Wrapf("cannot unmarshal V3 authorization data structure ({{err}})", err)
		}

		if v3Rec.AreaNid == 0 || !suppliesKeyAndSecret(&v3Rec) {
			return nil, errors.New("insufficient data to generate V2 signature")
		}

		now := time.Now().Unix()

		hash := md5.New()
		hash.Write([]byte(fmt.Sprintf("%s%s%d", v3Rec.ApiKey, v3Rec.KeySecret, now)))

		resp := b.Secret(secretMasheryV2Access).Response(map[string]interface{}{
			secretAreaNidField:      v3Rec.AreaNid,
			secretQpsField:          v3Rec.MaxQPS,
			secretApiKeField:        v3Rec.ApiKey,
			secretSignedSecretField: hex.EncodeToString(hash.Sum(nil)),
		}, map[string]interface{}{})

		return resp, nil
	}
}
