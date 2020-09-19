'use strict';

const jlincJwt = require('jlinc-jwt');
const createNonce = require('./createNonce');

module.exports = function(verifiedRequest, verifierKeys, verifierDid){
  //const { JlincDidAuthError } = this;

  /*
    The challenge object encapsulated in the returned JWS is the request object, plus the
    verifier's DID, the challenge nonce and a challenge timestamp in iat format.
    The JWS is signed with the verifier's DID signing key.
  */

  if (!verifiedRequest) throw new Error(`verifiedRequest object is required`);
  if (!verifierKeys || !verifierKeys.signingPublicKey) throw new Error(`verifier public key is required`);
  if (!verifierKeys || !verifierKeys.signingPrivateKey) throw new Error(`verifier private key is required`);
  if (!verifierDid) throw new Error(`verifier DID is required`);

  const challenge = createNonce();
  const challengeTs = Date.now();
  verifiedRequest.challenge = challenge;
  verifiedRequest.challengeIat = challengeTs;
  verifiedRequest.challengerDid = verifierDid;

  const challengeJWS = jlincJwt.signEdDsa(verifiedRequest, verifierKeys.signingPublicKey, verifierKeys.signingPrivateKey, verifierDid);

  return challengeJWS;
};
