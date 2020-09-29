'use strict';

const jwt = require('jlinc-jwt');
const { generateChallenge } = require('../helpers');
const auth = require('../../');

describe('signChallenge', function() {

  context('when given a valid challenge object', function(){
    it('should return a signed challengeJWS', function(){
      const {
        agentAuthReqURL,
        agentSigningKeys,
        agentDID,
        requesterDID,
        verifierDid,
        requesterKeys,
        challenge,
      } = generateChallenge();

      const signedChallenge = auth.signChallenge(
        challenge,
        requesterKeys,
        agentSigningKeys,
      );

      expect(signedChallenge).to.be.aJWT();

      const result = jwt.verifyEdDsa(signedChallenge);
      expect(result).to.matchPattern({
        signed: _.isString,
        signature: _.isString,
        header: {
          alg: 'EdDSA',
          typ: 'JWT',
          jwk: {
            kty: 'OKP',
            crv: 'Ed25519',
            x: agentSigningKeys.signingPublicKey,
          },
        },
        payload: {
          agentAuthReqURL,
          agentDID,
          requesterDID,
          iat: _.isIAT,
          authId: _.isAuthId,
          agentPublicKey: agentSigningKeys.signingPublicKey,
          challenge: _.isNonce,
          challengeIat: _.isIAT,
          challengerDid: verifierDid,
          requesterSignature: _.isB64,
          signatureIat: _.isIAT,
        },
      });
    });
  });

  context('when given an invalid challenge object', function(){
    it('should throw error', function(){
      expect(() => {
        auth.signChallenge({});
      }).to.throw(/signing error/);
    });
  });
});
