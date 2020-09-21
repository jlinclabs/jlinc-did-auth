'use strict';

class JlincDidAuthError extends Error {
  constructor(message){
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
};

module.exports =  {
  version: require('../package.json').version,

  // *** utiliies ***
  // Custom Errors
  JlincDidAuthError,

  // Create a nonce
  createNonce: require('./createNonce'),

  // *** requester methods ***
  // Create request for authorization
  request: require('./request'),

  // Verify a challenge JWS
  verifyChallenge: require('./verifyChallenge'),

  // Sign a challenge JWS
  signChallenge: require('./signChallenge'),


  // *** verifier methods ***
  // Verify request for authorization
  verifyReq: require('./verifyReq'),

  // Create a challenge JWS
  createChallenge: require('./createChallenge'),

  // Verify challenge signature
  verifyChallengeSignature: require('./verifyChallengeSignature'),

};
