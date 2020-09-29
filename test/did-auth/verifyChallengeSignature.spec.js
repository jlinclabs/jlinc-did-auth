'use strict';

const { generateSignedChallenge } = require('../helpers');
const auth = require('../../');

describe('verifyChallengeSignature', function() {

  context('when given a valid signed challenge JWS', function(){
    it('should return a validated signed challenge object', function(){
      const {
        agentAuthReqURL,
        agentDID,
        verifierDid,
        requesterDID,
        agentSigningKeys,
        signedChallenge,
      } = generateSignedChallenge();

      const result = auth.verifyChallengeSignature(signedChallenge);
      expect(result).to.matchPattern({
        agentAuthReqURL: agentAuthReqURL,
        agentDID: agentDID,
        requesterDID: requesterDID,
        iat: _.isIAT,
        authId: _.isUUIDv4,
        agentPublicKey: agentSigningKeys.signingPublicKey,
        challenge: _.isNonce,
        challengeIat: _.isIAT,
        challengerDid: verifierDid,
        requesterSignature: _.isString,
        signatureIat: _.isIAT,
      });
    });
  });

  context('when given an invalid request JWS', function(){
    it('should throw error', function(){
      expect(() => {
        auth.verifyChallengeSignature('asdsadasd.asdassad.asdsadsad');
      }).to.throw('Invalid JWS');
    });
  });
});
