# JLINC DID Auth

## Expected Usage
given:

```js
const auth = require('jlinc-did-auth');
```
### Request for authorization
```js
/*
  Format a request for authorization, a JWS to be transmitted to the authorizer.

  reqObject is an object with the following keys:
    {
      agentAuthReqURL,
      agentDID,
      agentSigningKeys,
      requesterDID
    }
  agentAuthReqURL is the API endpoint at which the agent expects to receive the auth challenge
*/

auth.request(reqObject) --> JWS
```
