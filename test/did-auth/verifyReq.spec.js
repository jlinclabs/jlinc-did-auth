'use strict';

const { generateRequestJWT } = require('../helpers');
const auth = require('../../');

describe('verifyReq', function() {

  context('when given a valid request JWS', function(){
    it('should return a validated request object', function(){
      const {
        agentAuthReqURL,
        agentDID,
        requesterDID,
        agentSigningKeys,
        requestJWT,
      } = generateRequestJWT();

      const result = auth.verifyReq(requestJWT);
      expect(result).to.matchPattern({
        agentAuthReqURL: agentAuthReqURL,
        agentDID: agentDID,
        requesterDID: requesterDID,
        iat: _.isIAT,
        authId: _.isAuthId,
        agentPublicKey: agentSigningKeys.signingPublicKey,
      });
    });
  });

  context('when given an invalid request JWS', function(){
    it('should throw error', function(){
      expect(() => {
        auth.verifyReq('asdsdasd.asdasdasd.asdasds');
      }).to.throw('Invalid JWS');
    });
  });
});
