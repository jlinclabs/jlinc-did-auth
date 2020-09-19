'use strict';

const auth = require('jlinc-did-auth');
const jwt = require('jlinc-jwt');
const isJWT = /^[\w-]+\.[\w-]+\.[\w-]+$/;
const isTimestamp = /^[\d]{10,13}$/; //with or without milliseconds
const isDid = /^did\:[a-z]+\:[\w\-]+$/;
const isNonce = /^[a-f0-9]{64}$/;
const validReqObject = {
  agentAuthReqURL: 'http://localhost:8080',
  agentDID: 'did:jlinc:mY5q2_qiJaaoQDMTdLj56tkP52iUxXg0pSb8u-S1iA0',
  agentSigningKeys: {signingPublicKey: 'mY5q2_qiJaaoQDMTdLj56tkP52iUxXg0pSb8u-S1iA0',
    signingPrivateKey: 'atlovbiCQUWv5lHkRohXluNvP69z6GXZ4dvAfBeTLUuZjmrb-qIlpqhAMxN0uPnq2Q_naJTFeDSlJvy75LWIDQ'},
  requesterDID: 'did:jlinc:iC2FSXaxH8HmK8sA0O6G3ZBVXpwb3IA_XfrYQDwnGE8'
};
const reqJWS = auth.request(validReqObject);
const verifiedRequest = auth.verifyReq(reqJWS);
const verifierKeys = {
  signingPublicKey: 'XJVzCMAArF4YAhHLQgOv58TLxxDS2IFi-8iNfrxYsZQ',
  signingPrivateKey: 'KyyAayH9nn-QU22WTjI1KFIs9ujI9YmcMmduwUwtmBBclXMIwACsXhgCEctCA6_nxMvHENLYgWL7yI1-vFixlA'
};
const verifierDid = 'did:jlinc:XJVzCMAArF4YAhHLQgOv58TLxxDS2IFi-8iNfrxYsZQ';

describe('create challenge', function() {

  context('when given a verified request, verifier keys, and verifier DID', function(){
    const result = auth.createChallenge(verifiedRequest, verifierKeys, verifierDid);
    it('should return a verifiable JWT', function(){
      expect(isJWT.test(result)).to.be.true;
      const verified = jwt.verifyEdDsa(result);
      expect(verified).to.be.an('object');
      expect(Object.keys(verified.payload)).to.have.lengthOf(9);
      expect(isNonce.test(verified.payload.challenge)).to.be.true;
      expect(isTimestamp.test(verified.payload.challengeIat)).to.be.true;
      expect(isDid.test(verified.payload.challengerDid)).to.be.true;
    });
  });

  context('when given invalid arguments', function(){
    it('should throw error', function(){
      expect(() => {
        auth.createChallenge();
      }).to.throw('verifiedRequest object is required');
    });
  });

  context('when given invalid arguments', function(){
    it('should throw error', function(){
      expect(() => {
        auth.createChallenge(verifiedRequest);
      }).to.throw('verifier public key is required');
    });
  });

  context('when given invalid arguments', function(){
    it('should throw error', function(){
      expect(() => {
        auth.createChallenge(verifiedRequest, {signingPublicKey: 'XJVzCMAArF4YAhHLQgOv58TLxxDS2IFi-8iNfrxYsZQ'});
      }).to.throw('verifier private key is required');
    });
  });

  context('when given invalid arguments', function(){
    it('should throw error', function(){
      expect(() => {
        auth.createChallenge(verifiedRequest, verifierKeys);
      }).to.throw('verifier DID is required');
    });
  });


});
