## Overview

Spring OAuth2 Authorization Server that supports Client Credentials Flow.

## Example Request

```
curl --location --request POST 'http://localhost:9000/oauth2/token' \
--header 'Authorization: Basic dGVzdDpwYXNzd29yZA==' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'scope=write' \
--data-urlencode 'grant_type=client_credentials'
```