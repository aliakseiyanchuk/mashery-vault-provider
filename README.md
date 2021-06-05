# Mashery V2/V3 Secrets Engine for HashiCorp Vault

[TIBCO Mashery](https://www.tibco.com/products/api-management) is an API management platform The platform
supports [programmatic access and configuration definition](https://developer.mashery.com/docs/read/mashery_api) that
requires two distinct authentication mechanisms. Mashery V2
uses [timestamp-salted MD5 hashes](https://developer.mashery.com/docs/read/mashery_api/20/Authentication)
while V3 api is using [access tokens](https://developer.mashery.com/docs/read/mashery_api/30/Authentication).

Both schemes are derived from a set of long-term credentials. Theoretically, standard
[key-value](https://www.vaultproject.io/docs/secrets/kv/kv-v2) would be sufficient to distribute these secrets to the
trusted applications and/or users. However, applications may _inadvertently_ write these into log file; users may enter
these into share workspace environment variables. Or the users may leave your organization and still have active keys
Mashery V2/V3 credentials.

This secret engine is intended for the contexts requiring very high degree of confidentiality for managing Mashery
credentials distributed to the Mashery administrators, such that administrators should have _no physical means_ to
expose these credentials.

This secret engine achieves this by encapsulating parts of the Mashery authentication credentials that are never
disclosed to the authorized lessor (application or person being granted
a [lease](https://www.vaultproject.io/docs/concepts/lease)). Instead, the lessor is granted short-lived credentials that
self-expire. Specifically, the lessor will _never_ know:

- Mashery key secret;
- Mashery administrator username;
- Mashery administrator password.

## Installing plugin

The plugin is installed with the `secrets enable` command. Given a very flexible nature of Vault product, an exact
command will vary depending on the deployment specifics. The examples in this guide will assume that the vault has been
started with `-dev-plugin-dir=./vault/plugins` option, and the binary file name is `mashery-api-auth_0.1` which is
symlinked to the executable appropriate to the host operating system.

The plugin is installed on `mash-auth` path using this command:

````text
$ vault secrets enable -path=mash-auth mashery-api-auth_0.1
````

> Note: `mash-auth` is just a mounting name that will be used in this readme. Any other meaningful
> name can be selected, if desired.

## Paths structure. Logical credentials name

As a team or an organization, multiple sets of Mashery credentials will be managed for different purposes. Each such set
of credentials should be given an organization-wide, distinct, descriptive
_logical credentials name_. Based on logical credentials name, the plugin supports three paths:

- `credentials/{logicalName}`: for storing and updating individual fields;
- `auth/{logicalName}/v2`: extract (one-time) signature for V2 API authentication;
- `auth/{logicalName}/v3`: extract access token for V3 API authentication.

## Writing values

Mashery V2/V3 API credentials can be either written with `write` command, or directly using Vault API. The administrator
should provide the following elements:

- credentials logical name. This would be inferred from the path;
- `area_id`: Mashery area UUID;
- `area_nid`: Mashery are numeric ID, required for V2 API;
- `api_key`: Mashey API key
- `secret`: Mashey API secret
- `username`: Mashery API username
- `password`: Mashery API user password
- `qps`: number, specifying the maximum queries-per-second (hereinafter referred to as QPS) the lessor should use. This
  value should not exceed the maximum QPS assigned to the Mashery API key, but could be lower if the key is shared
  between applications and/or users. If not specified, then QPS
- `lease_duration`: duration of a lease, in seconds.

Depending on the intended use, a subset of elements may be provided as indicated in the table below.

| Field | Required for V2 API | Required for V3 API |
|-------------------|-----|-----|
| `area_id`         |     | Yes |
| `area_nid`        | Yes |     |
| `api_key`         | Yes | Yes | 
| `secret`          | Yes | Yes |
| `username`        |     | Yes |
| `password`        |     | Yes |
| `qps`             | Yes | Yes |
| `lease_duration`  |     | Yes |

## Obtaining V2 credentials

The V2 credentials are read with using `read` command or API. Given a short-lived nature of V2 tokens,
console read could be useful to validate the correctness of the data entry.

```text
$ vault read mash-auth/auth/{credentials}/v2
```
This would print an output similar to the following:
```text
Key                Value
---                -----
lease_id           mash-auth/auth/my1/v2/R7TYsJpALg73GxPGvttVrROg
lease_duration     1m
lease_renewable    false
api_key            vv
area_nid           345
qps                2
sig                6647b1f113cd8c08a56a1367615af45f
```
> Note that the least duration is set to 1 minute. Due to technical nature of the Mashery V2 API
> authentication, the generated secret is non-revocable and will be rendered unusable in 5 minutes.
> Applications using these tokens should fetch replacement signature every minute.
>

To read the signature programmatically, Vault API could be use e.g. as follows:
```text
curl --location --request GET 'https://vault-host:8200/v1/mash-auth/auth/exampleCreds/v2' \
--header 'X-Vault-Token: root'
```
This command would yield the following results:
```json
{
    "request_id": "5888b776-c363-70d4-e8ed-92b28fdd50c5",
    "lease_id": "mash-auth/auth/my1/v2/Jg5Ee72LKK7D25LrypAOT7h9",
    "renewable": false,
    "lease_duration": 60,
    "data": {
        "api_key": "vv",
        "area_nid": 345,
        "qps": 2,
        "sig": "8cb4a71740462854ad2e728c9ac44873"
    },
    "wrap_info": null,
    "warnings": null,
    "auth": null
}
```

## Obtaining V3 credentials

Reading V3 credentials is also read either using the CLI or API interface.

```text
$ vault read mash-auth/auth/{credentials}/v3
```
This would print the output that would be similar to:
```text
Key                Value
---                -----
lease_id           mash-auth/auth/{credentials}/v3/r2WA3tCBopF0gtPk3rOgwzvV
lease_duration     15m
lease_renewable    true
access_token       accessTokenValue12345678
qps                2
```
Note that the access token is leased by default for 15 minutes. After 15 minutes, the token will be
revoked. Depending on circumstances, three strategies could be used to expand the duration of
the access token:
- configure different lease duration for the credentials by providing `lease_duration` field;
- program the application to renew the lease before it expires using `lease renew` command (or similar [API call](https://www.vaultproject.io/api-docs/system/leases)).
  > Note: Mashery access token have maximum lifetime of 1 hour, after which the lease will not be possible
  > to extend.
- program the application to request new tokens before the lease duration will expire.

## Building from sources

Building from sources requires go 1.15 or later and make utility installed.
```text
$ make vendor release
```
For Windows-based machines, [Cygwin](https://www.cygwin.com/install.html) provides a working
implementation of make tool. Alternatively, file `compile_win_amd64.bat` provides an option
to build Windows-only executable.