'use strict';

const jlincJwt = require('jlinc-jwt');
const uuid = require('uuid');

module.exports = function request(reqObject){
  const { JlincDidAuthError } = this;

  if (!reqObject) throw new Error(`request object is required`);
  if (!reqObject.agentAuthReqURL) throw new Error(`agentAuthReqURL is required`);
  if (!reqObject.agentDID) throw new Error(`agentDID is required`);
  if (!reqObject.agentSigningKeys) throw new Error(`agentSigningKeys is required`);
  if (!reqObject.requesterDID) throw new Error(`requesterDID is required`);

  const didRegex = /^did:[a-z]+:[\w\-]+$/;

  if (!didRegex.test(reqObject.agentDID))
    throw new JlincDidAuthError("RequestError: agentDID not a valid DID");

  if (!didRegex.test(reqObject.requesterDID))
    throw new JlincDidAuthError("RequestError: requesterDID not a valid DID");

  const authRequest = {};
  authRequest.agentAuthReqURL = reqObject.agentAuthReqURL;
  authRequest.agentDID = reqObject.agentDID;
  authRequest.requesterDID = reqObject.requesterDID;
  authRequest.iat = Date.now();
  authRequest.authId = uuid.v4();

  const authReqJws = jlincJwt.signEdDsa(
    authRequest,
    reqObject.agentSigningKeys.signingPublicKey,
    reqObject.agentSigningKeys.signingPrivateKey,
    reqObject.agentDID,
  );

  return authReqJws;
};
