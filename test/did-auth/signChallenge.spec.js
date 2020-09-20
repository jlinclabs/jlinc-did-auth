'use strict';

const auth = require('jlinc-did-auth');
const jwt = require('jlinc-jwt');
const isB64 = /^[\w\-]+$/;
const isTimestamp = /^[\d]{10,13}$/; //with or without milliseconds
const isJWT = /^[\w-]+\.[\w-]+\.[\w-]+$/;
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

const requesterKeys = {
  signingPublicKey: 'iC2FSXaxH8HmK8sA0O6G3ZBVXpwb3IA_XfrYQDwnGE8',
  signingPrivateKey: '3_NaynBoz--j4HUxvLtD0RhPuryFYiloWNXNgnOPBaWILYVJdrEfweYrywDQ7obdkFVenBvcgD9d-thAPCcYTw'
};

const reqJWS = auth.request(validReqObject);
const verifiedRequest = auth.verifyReq(reqJWS);
const challengeJWS = auth.createChallenge(verifiedRequest, verifierKeys, verifierDid);
const challengeObj = auth.verifyChallenge(challengeJWS);

describe('sign challenge', function() {

  context('when given a valid challenge object', function(){
    const signedChallengeJWS = auth.signChallenge(challengeObj, requesterKeys, validReqObject.agentSigningKeys);
    it('should return a signed challengeJWS', function(){
      expect(isJWT.test(signedChallengeJWS)).to.be.true;
      const verified = jwt.verifyEdDsa(signedChallengeJWS);
      expect(verified).to.be.an('object');
      expect(Object.keys(verified.payload)).to.have.lengthOf(11);
      expect(isB64.test(verified.payload.requesterSignature)).to.be.true;
      expect(isTimestamp.test(verified.payload.signatureIat)).to.be.true;
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
