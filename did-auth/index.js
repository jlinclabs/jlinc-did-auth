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

  // Custom Errors
  JlincDidAuthError,

  contextUrl: 'https://protocol.jlinc.org/context/jlinc-did-auth-v1.jsonld',

  // Create a nonce
  createNonce: require('./createNonce'),

  // Create request for authorization
  request: require('./request'),

  // Verify request for authorization
  verifyReq: require('./verifyReq'),

  // Create a challenge JWS
  createChallenge: require('./createChallenge'),

  // Verify a challenge JWS
  verifyChallenge: require('./verifyChallenge'),

  // Sign a challenge JWS
  signChallenge: require('./signChallenge'),

  // Verify challenge signature
  verifyChallengeSignature: require('./verifyChallengeSignature'),

};
