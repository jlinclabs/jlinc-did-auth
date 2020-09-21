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

## Protocol
1. The agent forms a request for authorization on behalf or the requester using #request and transmits the resulting JWS to the verifier's API endpoint.
2. The verifier decodes and validates the request using #verifyReq. They check that the agent DID is whitelisted, and cache the authID with the requester DID.
3. The verifier forms a challenge JWS using #createChallenge and transmits it to the agent's API endpoint.
4. The agent decodes and validates the challenge using #verifyChallenge and checks that the authID and all DIDs are as expected.
5. The agent then signs the resulting challengeObject using #signChallenge and and sends the requester to the verifier's authentication page with the signed challenge JWS.
6. The verifier decodes and validates the signed challenge JWS using #verifyChallengeSignature, and inspects the resulting data object for the correct authID and DIDs. If all is well, the verifier authorizes the requester.


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

auth.request(reqObject) --> JWS
```

### Verify request
```js
/*
  Verify the request for authorization for JWS signature and format completeness.
*/

auth.verifyReq(JWS) --> requestObject
```

### Create challenge
```js
/*
  The challenge object encapsulated in the returned JWS is the request object, plus the
  verifier's DID, the challenge nonce and a challenge timestamp in iat format.
  The JWS is signed with the verifier's DID signing key.
*/
auth.createChallenge(verifiedRequestObject, verifierKeys, verifierDid) --> challengeJWS
```

### Verify challenge
```js
/*
  Decode and verify the challenge.
*/

auth.verifyChallenge(challengeJWS) --> requestObject
```

### Sign challenge
```js
/*
  The challenge object plus signature over the nonce, by the requester DID's signing key, in Base64URL format, and a signature timestamp.
  The JWS is once again signed by the originating agentDID.
*/
auth.signChallenge(challengeObject, requesterKeys, agentKeys) --> signedChallengeJWS
```


### Verify challenge signature
```js
/*
  Verify the challenge signature, the JWS signature and format completeness.
  Return the signed challenge object.
*/

auth.verifyChallengeSignature(signedChallengeJWS) --> decodedSignedChallengeObject
```
