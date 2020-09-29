'use strict';

const jlincJwt = require('@jlinc/jwt');

module.exports = function verifyChallengeSignature(signedChallengeJWS){
  const { JlincDidAuthError } = this;

  let signedChallengeObj;
  try {
    signedChallengeObj = jlincJwt.verifyEdDsa(signedChallengeJWS);
  } catch (e) {
    throw new JlincDidAuthError('Invalid JWS');
  }

  if (!signedChallengeObj.payload.challenge) {
    throw new JlincDidAuthError('There is no challenge to verify');
  }
  if (!signedChallengeObj.payload.requesterSignature) {
    throw new JlincDidAuthError('There is no challenge signature to verify');
  }
  return signedChallengeObj.payload;
};
