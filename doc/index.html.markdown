---
layout: docs
page_title: TIBCO Mashery V2/V3 Secrets Engine
description: |-
The TIBCO Mashery V2/V3 Secrets engine generates md5 signatures (for V2 Mashery API) and access/refresh
tokens (for V3 Mashery API). 
---

# TIBCO Mashery Secrets Engine

TIBCO Mashery V2/V3 API use two distinct authentication mechanisms:
- V2 API is using one-time encrypted salted passwords, whereas
- V3 API us using refreshable OAuth access tokens.

This secret engine provides methods for one-way writing and retrieving the access credentials
for the Vault users/application that are authorized to access this secret.

## Setup

1. Supply the credentials via `/sites` endpoint


## Usage

After the Mashery keys and user ids have been saved, it can generate credentials

1. Generate new Mashery V2 credentials from the `/creds/v2` endpoint and the name of the
   site:
   
    ```text
     $ vault read masheryv3/creds/qa
       site_id: 5990
       apikey: <key>
       sig: <signature>
     ```