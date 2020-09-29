'use strict';

const { generateChallenge } = require('../helpers');
const auth = require('../../');

describe('verifyChallenge', function() {

  context('when given a valid challenge JWS', function(){
    it('should return a validated challenge object', function(){
      const {
        agentAuthReqURL,
        agentDID,
        requesterDID,
        agentSigningKeys,
        verifierDid,
        challengeJWS,
      } = generateChallenge();

      const result = auth.verifyChallenge(challengeJWS);
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
      });
    });
  });

  context('when given an invalid request JWS', function(){
    it('should throw error', function(){
      expect(() => {
        auth.verifyChallenge('xcxzcxc.zxcxzcxz.zxcxzc');
      }).to.throw('Invalid JWS');
    });
  });
});
