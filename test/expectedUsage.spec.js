'use strict';

const auth = require('../');
// const auth = require('@jlinc/did-auth');

const { generateActor } = require('./helpers');

it('Expected Usage', function(){
  const agentAuthReqURL = 'http://example.com/api/jlinc';

  const {
    did: requesterDID,
    signingKeys: requesterKeys,
  } = generateActor();

  const {
    did: agentDID,
    signingKeys: agentSigningKeys,
  } = generateActor();

  const  {
    did: verifierDid,
    signingKeys: verifierKeys,
  } = generateActor();

  const requestJWS = auth.request({
    agentAuthReqURL,
    agentDID,
    agentSigningKeys,
    requesterDID,
  });

  expect(requestJWS).to.be.aJWT();

  const request = auth.verifyReq(requestJWS);

  expect(request).to.matchPattern({
    agentAuthReqURL: agentAuthReqURL,
    agentDID: agentDID,
    requesterDID: requesterDID,
    iat: _.isIAT,
    authId: _.isUUIDv4,
    agentPublicKey: agentSigningKeys.signingPublicKey,
  });

  const challengeJWS = auth.createChallenge(
    request,
    verifierKeys,
    verifierDid,
  );

  expect(challengeJWS).to.be.aJWT();

  const challenge = auth.verifyChallenge(challengeJWS);

  expect(challenge).to.matchPattern({
    agentAuthReqURL,
    agentDID,
    requesterDID,
    iat: request.iat,
    authId: _.isUUIDv4,
    agentPublicKey: agentSigningKeys.signingPublicKey,
    challenge: _.isNonce,
    challengeIat: _.isIAT,
    challengerDid: verifierDid,
  });

  const signedChallengeJWS = auth.signChallenge(
    challenge,
    requesterKeys,
    agentSigningKeys,
  );

  expect(signedChallengeJWS).to.be.aJWT();

  const signedChallenge = auth.verifyChallengeSignature(signedChallengeJWS);

  expect(signedChallenge).to.deep.equal(challenge);

});
