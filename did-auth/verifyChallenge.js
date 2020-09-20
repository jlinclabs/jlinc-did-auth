'use strict';

const jlincJwt = require('jlinc-jwt');

module.exports = function(challengeJWS){
  const { JlincDidAuthError } = this;

  let challengeObj;
  try {
    challengeObj = jlincJwt.verifyEdDsa(challengeJWS);
  } catch (e) {
    throw new JlincDidAuthError('Invalid JWS');
  }

  if (!challengeObj.payload.challenge) {
    throw new JlincDidAuthError('There is no challenge to sign');
  }
  return challengeObj.payload;
};
