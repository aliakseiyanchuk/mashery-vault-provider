package mashery

import (
	"context"
	"fmt"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	credentialsName   = "masheryCredentialsName"
	pathAreasHelpSyn  = "Saves Mashery credentials"
	pathAreasHelpDesc = `
The path is write-only storage of Mashery credentials required to obtain the V2/V3 authentication tokens. This path 
is used first before authentication tokens can be retrieved. That path accepts configuration for both V2 and V3
Mashery API. The user is recommended to always follow the least-required principle and suppply only fields that are 
require for intended authentication methods.

An organization may operate multiple Mashery package keys that would be used for various purposes. Typically, these
are:
- Keys for testing purpose. These keys have relatively low qps and daily quota;
- Deployment pipeline keys. These keys would have relatively low qps and rather high daily quota; and
- OAuth server keys. These keys would have high qps as well as high daily quota that is commensurate with the number
  of access tokens created by the OAuth server.

Mashery credential logicl names should be descriptive, e.g. test, production, or test-oauth-server, 
prod-ci_cd-pipeline, etc. The actual tooling will need thus to refer only to the logical name of this site to retrieve 
access credentials.`
)

func pathAreaData(b *AuthPlugin) *framework.Path {
	return &framework.Path{
		Pattern: "credentials/" + framework.GenericNameWithAtRegex(credentialsName),
		Fields: map[string]*framework.FieldSchema{
			credentialsName: {
				Type:        framework.TypeString,
				Description: "Mashery Area logical name",
				DisplayName: "Area's logical name",
			},
			secretAreaIdField: {
				Type:        framework.TypeString,
				Description: "Mashery Area UUID. Required for V3 credentials",
				DisplayName: "Area UUID",
			},
			secretAreaNidField: {
				Type:        framework.TypeInt,
				Description: "Mashery Area Numeric ID. Required for V2 credentials",
				DisplayName: "Area NID",
			},
			secretApiKeField: {
				Type:             framework.TypeString,
				Description:      "Mashery API Key. Required for both V2 and V3 credentials",
				DisplayName:      "API Key",
				DisplaySensitive: true,
			},
			secretKeySecretField: {
				Type:             framework.TypeString,
				Description:      "Mashery API Key Secret. Required for both V2 and V3 credentials",
				DisplayName:      "API Key Secret",
				DisplaySensitive: true,
			},
			secretUsernameField: {
				Type:             framework.TypeString,
				Description:      "Mashery V3 API User. Required for V3 credentials",
				DisplayName:      "Mashery user",
				DisplaySensitive: true,
			},
			secretPasswordField: {
				Type:             framework.TypeString,
				Description:      "Mashery V3 API password. Required for V3 credentials",
				DisplayName:      "Mashery user password",
				DisplaySensitive: true,
			},
			secretQpsField: {
				Type:        framework.TypeInt,
				Description: "Maximum QPS this key can make. Recommended for all methods; defaults to 2",
				DisplayName: "Maximum V3 QPS",
				Default:     2,
			},
			secretLeaseDurationField: {
				Type:        framework.TypeDurationSecond,
				Description: "Lease duration (for the access token). Optional for V3 credentials",
				DisplayName: "Lease duration of V3 access token",
				Default:     900,
			},
		},

		ExistenceCheck: b.siteExistenceCheck,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.handleWriteAreaData,
				Summary:  "Store Mashery area authentication data",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleUpdateAreaData,
				Summary:  "Update Mashery area authentication data",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.handleDeleteAreaData,
				Summary:  "Delete area authentication data",
			},
		},
		HelpSynopsis:    pathAreasHelpSyn,
		HelpDescription: pathAreasHelpDesc,
	}
}

func (b *AuthPlugin) siteExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	if out, err := req.Storage.Get(ctx, storagePathForMasheryArea(data)); err != nil {
		return false, errwrap.Wrapf("existence check failed: {{err}}", err)
	} else {
		return out != nil, nil
	}
}

func storagePathForMasheryArea(data *framework.FieldData) string {
	siteName := data.Get(credentialsName).(string)

	return "area/" + siteName
}

func toV3AuthRec(b *AuthPlugin, data *framework.FieldData) AuthRec {
	retVal := AuthRec{}

	mergeSiteFieldsInto(data, &retVal)
	if retVal.LeaseDuration == 0 {
		retVal.LeaseDuration = 15 * 60
	}

	b.Logger().Info(fmt.Sprintf("Lease duration for access token is %d", retVal.LeaseDuration))
	return retVal
}

func mergeSiteFieldsInto(data *framework.FieldData, retVal *AuthRec) {
	if areaIdRaw, ok := data.GetOk(secretAreaIdField); ok {
		retVal.AreaId = areaIdRaw.(string)
	}
	if areaNidRaw, ok := data.GetOk(secretAreaNidField); ok {
		retVal.AreaNid = areaNidRaw.(int)
	}
	if apiKeyRaw, ok := data.GetOk(secretApiKeField); ok {
		retVal.ApiKey = apiKeyRaw.(string)
	}
	if keySecretRaw, ok := data.GetOk(secretKeySecretField); ok {
		retVal.KeySecret = keySecretRaw.(string)
	}
	if usernameRaw, ok := data.GetOk(secretUsernameField); ok {
		retVal.Username = usernameRaw.(string)
	}
	if passwordRaw, ok := data.GetOk(secretPasswordField); ok {
		retVal.Password = passwordRaw.(string)
	}

	if secretQpsRaw, ok := data.GetOk(secretQpsField); ok {
		retVal.MaxQPS = secretQpsRaw.(int)
	} else {
		retVal.MaxQPS = 2
	}

	if durationRaw, ok := data.GetOk(secretLeaseDurationField); ok {
		retVal.LeaseDuration = durationRaw.(int)

		if retVal.LeaseDuration == 0 {
			retVal.LeaseDuration = 15 * 60
		}
	}
}

func (b *AuthPlugin) handleWriteAreaData(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return persistAuthRecord(ctx, req, data, toV3AuthRec(b, data))
}

func persistAuthRecord(ctx context.Context, req *logical.Request, data *framework.FieldData, v3Rec AuthRec) (*logical.Response, error) {
	if se, err := logical.StorageEntryJSON(storagePathForMasheryArea(data), v3Rec); err != nil {
		return nil, errwrap.Wrapf("failed to save site data: {{err}}", err)
	} else {
		err = req.Storage.Put(ctx, se)
		return nil, err
	}
}

func getAuthRecord(ctx context.Context, req *logical.Request, data *framework.FieldData) (*AuthRec, error) {
	if entry, err := req.Storage.Get(ctx, storagePathForMasheryArea(data)); err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil
	} else {
		v3Rec := AuthRec{}

		if err := entry.DecodeJSON(&v3Rec); err != nil {
			return nil, errwrap.Wrapf("cannot unmarshal V3 authorization data structure ({{err}})", err)
		}

		return &v3Rec, nil
	}
}

func (b *AuthPlugin) handleUpdateAreaData(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if v3Rec, err := getAuthRecord(ctx, req, data); err != nil {
		return nil, err
	} else {
		mergeSiteFieldsInto(data, v3Rec)
		return persistAuthRecord(ctx, req, data, *v3Rec)
	}
}

func (b *AuthPlugin) handleDeleteAreaData(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, storagePathForMasheryArea(data))
	return nil, errwrap.Wrapf("failed to delete site data: {{err}}", err)
}
