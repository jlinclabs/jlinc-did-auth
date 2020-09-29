'use strict';

const jlincJwt = require('@jlinc/jwt');
const DID_FORMAT = /^did:[a-z]+:[\w-]+$/;

module.exports = function verifyReq(reqJWS){
  const { JlincDidAuthError } = this;

  let requestObj;
  try {
    requestObj = jlincJwt.verifyEdDsa(reqJWS);
  } catch (e) {
    throw new JlincDidAuthError('Invalid JWS');
  }

  const errorList = [];
  if (
    typeof requestObj.payload.agentAuthReqURL !== 'string' ||
    requestObj.payload.agentAuthReqURL === ''
  )
    errorList.push('agentAuthReqURL is missing');

  if (!DID_FORMAT.test(requestObj.payload.agentDID))
    errorList.push('agentDID is missing or malformed');

  if (!DID_FORMAT.test(requestObj.payload.requesterDID))
    errorList.push('requesterDID is missing or malformed');

  if (
    typeof requestObj.payload.iat !== 'number' ||
    requestObj.payload.iat.toString().length < 10
  )
    errorList.push('iat must be a unix timestamp');

  if (errorList.length > 0) throw new JlincDidAuthError(
    'The request payload had the following errors: ' +
    errorList.join(', ')
  );

  let payload = requestObj.payload;
  payload.agentPublicKey = requestObj.header.jwk.x;
  return payload;
};
