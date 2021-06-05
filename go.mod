module yanchuk.nl/hcvault-mashery-api-auth

go 1.12

require (
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-hclog v0.9.2
	//github.com/hashicorp/vault-guides/plugins/vault-plugin-secrets-mock v0.0.0-20201203172804-75fc2f42ebb0 // indirect
	github.com/hashicorp/vault/api v1.0.2
	github.com/hashicorp/vault/sdk v0.1.11

	github.com/aliakseiyanchuk/mashery-v3-go-client v0.0.0-20210110193017-ba218ef21d7e
)

replace github.com/aliakseiyanchuk/mashery-v3-go-client => ../mashery-v3-go-client