'use strict';

const jlincJwt = require('jlinc-jwt');
const sodium = require('sodium').api;
const b64 = require('urlsafe-base64');

module.exports = function(challengeObj, requesterKeys, agentKeys){
  const { JlincDidAuthError } = this;

  try {
    const signature = sodium.crypto_sign_detached(Buffer.from(challengeObj.challenge), b64.decode(requesterKeys.signingPrivateKey));
    challengeObj.requesterSignature = b64.encode(signature);
  } catch (e) {
    throw new JlincDidAuthError(`signing error: ${e.message}`);
  }

  challengeObj.signatureIat = Date.now();

  const signedChallengeJWS = jlincJwt.signEdDsa(challengeObj, agentKeys.signingPublicKey, agentKeys.signingPrivateKey, challengeObj.agentDid);

  return signedChallengeJWS;
};
