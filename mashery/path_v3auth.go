package mashery

import (
	"context"
	"errors"
	"fmt"
	"github.com/aliakseiyanchuk/mashery-v3-go-client/v3client"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"reflect"
	"time"
)

// Mashery V3 Authentication signature

const (
	pathV3CredentialsHelpSyn  = "Retrieves Mashery V3 API access token"
	pathV3CredentialsHelpDesc = `
Retrieves an access token and maximum queries-per-second (qps) value this token can use to query/modify objects
of the associated Mashery area. Prior issuing the token, the area credentials should be saved using areas/<credentialsName>
specifying:
- Area Id
- Mashery package key
- Mashery secret
- User name
- Password
- Optionally, lease duration of the access token.

Mashery V3 tokens are maximum valid for 1 hour. Most organization would wish to revoke this token after completion
of the necessary works. To fulfil this requirement, this secret engine will use default of 15 minutes for the lease.
This duration is sufficient for most deployment/query operations. Upon expiry, the granted access token will be 
revoked.

The lease duration of the provided access token can be changed either by extending the lease
up to the duration of the access token validity, or specifying a custom lease duration for this site.
`

	secretMasheryV3Access = "v3_access"
)

func v3AccessSecret(b *AuthPlugin) *framework.Secret {
	return &framework.Secret{
		Type: secretMasheryV3Access,
		Fields: map[string]*framework.FieldSchema{
			secretAccessToken: {
				Type:        framework.TypeString,
				Description: "Mashery V3 access token",
			},
			secretQpsField: {
				Type:        framework.TypeInt,
				Description: "Maximum QPS this token is granted",
			},
		},
		DefaultDuration: time.Minute * 15,
		Revoke:          b.revokeV3AccessToken,
		Renew:           b.extendV3AccessTokenLease,
	}
}

func pathV3Credentials(b *AuthPlugin) *framework.Path {
	return &framework.Path{
		Pattern: "auth/" + framework.GenericNameWithAtRegex(credentialsName) + "/v3",
		Fields: map[string]*framework.FieldSchema{
			credentialsName: {
				Type:        framework.TypeString,
				Description: "Mashery area logical name",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathReadV3Credentials,
				Summary:  "Retrieve V3 access token",
			},
		},

		ExistenceCheck: b.siteExistenceCheck,

		HelpSynopsis:    pathV3CredentialsHelpSyn,
		HelpDescription: pathV3CredentialsHelpDesc,
	}
}

func sufficientForV3(v3Rec *AuthRec) bool {
	return len(v3Rec.AreaId) > 0 &&
		suppliesKeyAndSecret(v3Rec) &&
		len(v3Rec.Username) > 0 && len(v3Rec.Password) > 0
}

func min(x, y int) int {
	if x > y {
		return y
	} else {
		return x
	}
}

func max(x, y time.Duration) time.Duration {
	if x > y {
		return x
	} else {
		return y
	}
}

func (b *AuthPlugin) pathReadV3Credentials(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if v3Rec, err := getAuthRecord(ctx, req, d); err != nil {
		return nil, errwrap.Wrapf("cannot read site credentials: {{err}", err)
	} else if v3Rec == nil {
		return nil, errors.New("nil authorization data structure returned")
	} else if !sufficientForV3(v3Rec) {
		return nil, errors.New("site data is not sufficient to request v3 access token")
	} else {
		// We have site data and site dat is sufficient to produce credentials.
		v3Credentials := v3Rec.asV3Credentials()
		if tkn, err := b.v3OauthHelper.RetrieveAccessTokenFor(&v3Credentials); err != nil {
			return nil, errwrap.Wrapf("access token was not granted: {{err}", err)
		} else {
			return b.createSecretResponse(tkn, v3Rec, d), nil
		}
	}
}

func (b *AuthPlugin) createSecretResponse(tkn *v3client.TimedAccessTokenResponse, v3Rec *AuthRec, d *framework.FieldData) *logical.Response {
	exp := time.Now().Add(time.Second * time.Duration(tkn.ExpiresIn))

	b.Logger().Info("Maximum token expiry time", "exp", exp.Unix())

	response := b.Secret(secretMasheryV3Access).Response(map[string]interface{}{
		secretAccessToken: tkn.AccessToken,
		secretQpsField:    v3Rec.MaxQPS,
	}, map[string]interface{}{
		secretInternalSiteStoragePath: storagePathForMasheryArea(d),
		secretInternalRefreshToken:    tkn.RefreshToken,
		secretInternalTokenExpiryTime: exp.Unix(),
	})

	usableTokenTime := min(v3Rec.LeaseDuration, tkn.ExpiresIn)
	b.Logger().Info(fmt.Sprintf("Usable token time in seconds: %d, chosen from %d lead duration and %d exipry time", usableTokenTime, v3Rec.LeaseDuration, tkn.ExpiresIn))

	response.Secret.LeaseOptions.TTL = time.Second * time.Duration(usableTokenTime)
	response.Secret.LeaseOptions.MaxTTL = max(time.Hour*1, time.Second*time.Duration(usableTokenTime))

	b.Logger().Info(fmt.Sprintf("Response TTL %s", response.Secret.LeaseOptions.TTL))
	b.Logger().Info(fmt.Sprintf("Response Max TTL %s", response.Secret.LeaseOptions.MaxTTL))
	// Hard-coded limit
	return response
}

func (b *AuthPlugin) getAuthRecordOfSecret(ctx context.Context, req *logical.Request) (*AuthRec, error) {
	if req.Secret == nil || req.Secret.InternalData == nil {
		return nil, errors.New("request does not bear secret")
	}

	storagePathRaw := req.Secret.InternalData[secretInternalSiteStoragePath]
	b.Logger().Info("Secret internal storage path", "rawPath", storagePathRaw, "rawPathType", reflect.TypeOf(storagePathRaw).String())

	if storagePath, ok := storagePathRaw.(string); !ok {
		return nil, errors.New("cannot read storage path out of internal data")
	} else {
		if entry, err := req.Storage.Get(ctx, storagePath); err != nil {
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
}

func (b *AuthPlugin) extendV3AccessTokenLease(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	v3Rec, fetchErr := b.getAuthRecordOfSecret(ctx, req)
	b.Logger().Info("Fetched V3 record", "data", v3Rec, "error", fetchErr)

	var remainingTokenTime = 0
	var maxAllowedLease = 3600

	expRaw := req.Secret.InternalData[secretInternalTokenExpiryTime]
	b.Logger().Info("Expiry time raw", "raw", expRaw, "type", reflect.TypeOf(expRaw).String())

	if expConv, ok := expRaw.(float64); ok {
		remainingTokenTime = int(int64(expConv) - time.Now().Unix())
	}

	b.Logger().Info("Remaining token time", "token", remainingTokenTime)
	if remainingTokenTime <= 0 {
		return nil, errors.New("lease cannot be renews as token has expired")
	} else if remainingTokenTime <= 15 {
		//
		return nil, errors.New("lease almost expired, request new one instead")
	}

	if v3Rec != nil && v3Rec.LeaseDuration > 0 {
		maxAllowedLease = v3Rec.LeaseDuration
	}

	usableTokenTime := min(remainingTokenTime, maxAllowedLease)
	b.Logger().Info(fmt.Sprintf("Usable token time in seconds: %d, chosen from %d seconds lead duration and remaining %d seconds exipry time", usableTokenTime, maxAllowedLease, remainingTokenTime))

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = time.Duration(usableTokenTime) * time.Second

	return resp, nil
}

func (b *AuthPlugin) revokeV3AccessToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if v3Rec, err := b.getAuthRecordOfSecret(ctx, req); err != nil {
		return nil, errwrap.Wrapf("error in retrieving v3 authentication record: {{err}}", err)
	} else if v3Rec != nil && suppliesKeyAndSecret(v3Rec) {
		v3Credentials := v3Rec.asV3Credentials()
		// An attempt is made to invoke the refresh token, which will invalidate the current access token.
		if _, err = b.v3OauthHelper.ExchangeRefreshToken(&v3Credentials, req.Secret.InternalData[secretInternalRefreshToken].(string)); err != nil {
			b.Logger().Error("Error returned while trying to invoke an exchange token", "error", err)
		}
	}

	// Access token cannot be revoked forcibly and should expire by itself.
	return nil, nil
}
