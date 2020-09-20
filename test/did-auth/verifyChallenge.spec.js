'use strict';

const auth = require('jlinc-did-auth');
const isNonce = /^[a-f0-9]{64}$/;
const isTimestamp = /^[\d]{10,13}$/; //with or without milliseconds
const validReqObject = {
  agentAuthReqURL: 'http://localhost:8080',
  agentDID: 'did:jlinc:mY5q2_qiJaaoQDMTdLj56tkP52iUxXg0pSb8u-S1iA0',
  agentSigningKeys: {signingPublicKey: 'mY5q2_qiJaaoQDMTdLj56tkP52iUxXg0pSb8u-S1iA0',
    signingPrivateKey: 'atlovbiCQUWv5lHkRohXluNvP69z6GXZ4dvAfBeTLUuZjmrb-qIlpqhAMxN0uPnq2Q_naJTFeDSlJvy75LWIDQ'},
  requesterDID: 'did:jlinc:iC2FSXaxH8HmK8sA0O6G3ZBVXpwb3IA_XfrYQDwnGE8'
};
const verifierKeys = {
  signingPublicKey: 'XJVzCMAArF4YAhHLQgOv58TLxxDS2IFi-8iNfrxYsZQ',
  signingPrivateKey: 'KyyAayH9nn-QU22WTjI1KFIs9ujI9YmcMmduwUwtmBBclXMIwACsXhgCEctCA6_nxMvHENLYgWL7yI1-vFixlA'
};
const verifierDid = 'did:jlinc:XJVzCMAArF4YAhHLQgOv58TLxxDS2IFi-8iNfrxYsZQ';

const reqJWS = auth.request(validReqObject);
const verifiedRequest = auth.verifyReq(reqJWS);
const challengeJWS = auth.createChallenge(verifiedRequest, verifierKeys, verifierDid);

describe('verify challenge', function() {

  context('when given a valid challenge JWS', function(){
    const result = auth.verifyChallenge(challengeJWS);
    it('should return a validated challenge object', function(){
      expect(result).to.be.an('object');
      expect(Object.keys(result)).to.have.lengthOf(9);
      expect(isNonce.test(result.challenge)).to.be.true;
      expect(isTimestamp.test(result.challengeIat)).to.be.true;
    });
  });

  context('when given an invalid request JWS', function(){
    it('should throw error', function(){
      const invalidJWS = challengeJWS.slice(0,-1);
      expect(() => {
        auth.verifyChallenge(invalidJWS);
      }).to.throw('Invalid JWS');
    });
  });
});
