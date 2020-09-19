# JLINC DID Auth

## Actors and prerequisites
The actors in this protocol are an entity requesting authentication ( the ***requester*** ),
a software agent for the requestor ( the ***agent*** ), and a service that authenticates the
requester ( the ***verifier*** ).

Each of these parties must have their own DID.

The ***agent*** must have access to the requester's
signing key (the private or secret part of the signing keypair) in order to sign requests on its behalf,
as well as their own signing key to validate their JWS's.

The ***verifier*** must have access to their own signing key for JWS validation.

Both the ***agent*** and the ***verifier*** should keep a whitelist of acceptable counter-party's DIDs and
associated public keys. 

## Expected Usage
given:

```js
const auth = require('jlinc-did-auth');
```
### Request for authorization
```js
/*
  Format a request for authorization, a JWS to be transmitted to the authorizer.
  Required argument is the reqObject less the iat and authId values.

  reqObject is an object with the following keys:
    {
      agentAuthReqURL,
      agentDID,
      agentSigningKeys,
      requesterDID,
      iat,
      authId
    }
  agentAuthReqURL is the API endpoint at which the agent expects to receive the auth challenge.
  The iat is a timestamp (as defined in JWT) and should include millisecond value to help with uniqueness.
  The authID is a UUID of v4 type.
*/

auth.request({reqObject}) --> JWS
```

### Verify request
```js
/*
  Verify the request for authorization for JWS signature and format completeness.
*/

auth.verifyReq(JWS) --> requestObject
```

### Send challenge
```js
/*
  The challenge object encapsulated in the returned JWS is the request object, plus the
  verifier's DID, the challenge nonce and a challenge timestamp in iat format.
  The JWS is signed with the verifier's DID signing key.
*/
auth.challenge(requestObject) --> challengeJWS
```

### Sign challenge
```js
/*
  The challenge object plus signature over the nonce, by the requester DID's signing key, in Base64URL format, and a signature timestamp.
  The JWS is once again signed by the originating agentDID.
*/
auth.signChallenge(challengeJWS) --> signedChallengeJWS
```


### Verify challenge and issue token
```js
/*
  Verify the challenge signature, the JWS signature and format completeness.
  Return the signed challenge object, and a unique auth token.
*/

auth.verifyChallenge(signedChallengeJWS) --> {decodedSignedCallengeObject, token}
```
