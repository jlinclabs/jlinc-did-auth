'use strict';

const jwt = require('@jlinc/jwt');
const {
  generateVerifiedRequest,
  generateActor,
} = require('../helpers');
const auth = require('../../');

describe('createChallenge', function() {
  context('when given a verified request, verifier keys, and verifier DID', function(){
    it('should return a verifiable JWT', function(){
      const {
        agentAuthReqURL,
        requesterDID,
        agentDID,
        agentSigningKeys,
        verifiedRequest,
      } = generateVerifiedRequest();

      const  {
        did: verifierDid,
        signingKeys: verifierKeys,
      } = generateActor();

      const challenge = auth.createChallenge(
        verifiedRequest,
        verifierKeys,
        verifierDid,
      );

      expect(challenge).to.be.aJWT();
      const result = jwt.verifyEdDsa(challenge);

      expect(result).to.matchPattern({
        signed: _.isString,
        signature: _.isString,
        header: {
          alg: 'EdDSA',
          typ: 'JWT',
          jwk: {
            kty: 'OKP',
            crv: 'Ed25519',
            x: verifierKeys.signingPublicKey,
            kid: verifierDid,
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
        },
      });
    });
  });

  context('when given invalid verifiedRequest object', function(){
    it('should throw error', function(){
      expect(() => {
        auth.createChallenge();
      }).to.throw('verifiedRequest object is required');
    });
  });

  context('when given an invalid public key', function(){
    it('should throw error', function(){
      expect(() => {
        auth.createChallenge({
          verifierKeys: {},
        });
      }).to.throw('verifier public key is required');
    });
  });

  context('when given invalid private key', function(){
    it('should throw error', function(){
      expect(() => {
        auth.createChallenge(
          {},
          {
            signingPublicKey: 'XJVzCMAArF4YAhHLQgOv58TLxxDS2IFi-8iNfrxYsZQ'
          },
        );
      }).to.throw('verifier private key is required');
    });
  });

  context('when given no verifier DID', function(){
    it('should throw error', function(){
      expect(() => {
        auth.createChallenge(
          {},
          {
            signingPublicKey: 'y',
            signingPrivateKey: 'x',
          },
        );
      }).to.throw('verifier DID is required');
    });
  });

});
