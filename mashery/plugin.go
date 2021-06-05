package mashery

import (
	"context"
	"github.com/aliakseiyanchuk/mashery-v3-go-client/v3client"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
)

type AuthPlugin struct {
	*framework.Backend

	v3OauthHelper *v3client.V3OAuthHelper
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, _ := makeNew()
	setupErr := b.Setup(ctx, conf)
	if setupErr != nil {
		return nil, setupErr
	}

	return b, nil
}

func makeNew() (*AuthPlugin, error) {

	retVal := AuthPlugin{
		v3OauthHelper: v3client.NewOAuthHelper(),
	}

	retVal.Backend = &framework.Backend{
		Help:        strings.TrimSpace(pluginHelp),
		BackendType: logical.TypeLogical,
		Paths: []*framework.Path{
			pathAreaData(&retVal),
			pathV2Credentials(&retVal),
			pathV3Credentials(&retVal),
		},
		Secrets: []*framework.Secret{
			v2AccessSecret(&retVal),
			v3AccessSecret(&retVal),
		},
	}

	retVal.Logger().Info("Mashery V2/V3 authentication plugin has been initialized")
	return &retVal, nil
}

// noopRenewRevoke revocation of the secret that was issued
func (b *AuthPlugin) noopRenewRevoke(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
	return nil, nil
}

const pluginHelp = `Mashery V3 Authentication plugin used to generate V2 signatures and V3 access tokens.
`
