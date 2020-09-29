'use strict';

const b64 = require('urlsafe-base64');
const sodium = require('sodium').api;

const auth = require('../');

function generateUrl(){
  const port = Math.round(Math.random() * 10000);
  return `http://localhost:${port}`;
}

function generateSigningKeys(){
  const { publicKey, secretKey } = sodium.crypto_sign_keypair();
  return {
    signingPublicKey: b64.encode(publicKey),
    signingPrivateKey: b64.encode(secretKey),
  };
}

function generateActor(){
  const signingKeys = generateSigningKeys();
  const did = `did:jlinc:${signingKeys.signingPublicKey}`;
  return { did, signingKeys };
}

function generateDID(){
  const { did } = generateActor();
  return did;
}

function generateRequest(){
  const agentAuthReqURL = generateUrl();
  const {
    did: requesterDID,
    signingKeys: requesterKeys,
  } = generateActor();

  const {
    did: agentDID,
    signingKeys: agentSigningKeys,
  } = generateActor();

  const request = {
    agentAuthReqURL,
    agentDID,
    agentSigningKeys,
    requesterDID,
  };
  return {
    agentAuthReqURL,
    requesterDID,
    requesterKeys,
    agentDID,
    agentSigningKeys,
    request,
  };
}

function generateRequestJWT(){
  const {request, ...other} = generateRequest();
  const requestJWT = auth.request(request);
  return {...other, request, requestJWT};
}

function generateVerifiedRequest(){
  const {requestJWT, ...other} = generateRequestJWT();
  const verifiedRequest = auth.verifyReq(requestJWT);
  return {...other, requestJWT, verifiedRequest};
}

function generateChallenge(){
  const {
    verifiedRequest,
    ...other
  } = generateVerifiedRequest();

  const  {
    did: verifierDid,
    signingKeys: verifierKeys,
  } = generateActor();

  const challengeJWS = auth.createChallenge(
    verifiedRequest,
    verifierKeys,
    verifierDid,
  );
  const challenge = auth.verifyChallenge(challengeJWS);

  return {
    ...other,
    verifiedRequest,
    verifierKeys,
    verifierDid,
    challengeJWS,
    challenge,
  };
}

function generateSignedChallenge(){
  const {
    challenge,
    requesterKeys,
    agentSigningKeys,
    ...other
  } = generateChallenge();

  const signedChallenge = auth.signChallenge(
    challenge,
    requesterKeys,
    agentSigningKeys,
  );

  return {
    ...other,
    challenge,
    requesterKeys,
    agentSigningKeys,
    signedChallenge,
  };
}

module.exports = {
  generateUrl,
  generateSigningKeys,
  generateActor,
  generateDID,
  generateRequest,
  generateRequestJWT,
  generateVerifiedRequest,
  generateChallenge,
  generateSignedChallenge,
};
