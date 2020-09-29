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

1. The agent forms a request for authorization on behalf or the requester using `jlincDidAuth.request` and transmits the resulting JWS to the verifier's API endpoint.

2. The verifier decodes and validates the request using `jlincDidAuth.verifyReq`. They check that the agent DID is white-listed, and cache the authID with the requester DID.

3. The verifier forms a challenge JWS using `jlincDidAuth.createChallenge` and transmits it to the agent's API endpoint.

4. The agent decodes and validates the challenge using `jlincDidAuth.verifyChallenge` and checks that the authID and all DIDs are as expected.

5. The agent then signs the resulting challengeObject using `jlincDidAuth.signChallenge` and and sends the requester to the verifier's authentication page with the signed challenge JWS.

6. The verifier decodes and validates the signed challenge JWS using `jlincDidAuth.verifyChallengeSignature`, and inspects the resulting data object for the correct authID and DIDs. If all is well, the verifier authorizes the requester.


## Expected Usage

Checkout our [expected usage mocha spec](./test/expectedUsage.spec.js) for
a basic usage example.


## Terms

### `JWS`

[JSON Web Signature](https://en.wikipedia.org/wiki/JSON_Web_Signature)

### `JWT`

[JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token)
