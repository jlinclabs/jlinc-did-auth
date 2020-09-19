'use strict';

const auth = require('jlinc-did-auth');
const isB64 = /^[\w\-]+$/;
const isTimestamp = /^[\d]{10,13}$/; //with or without milliseconds
const isUUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12}$/; //v4 UUID
const validReqObject = {
  agentAuthReqURL: 'http://localhost:8080',
  agentDID: 'did:jlinc:mY5q2_qiJaaoQDMTdLj56tkP52iUxXg0pSb8u-S1iA0',
  agentSigningKeys: {signingPublicKey: 'mY5q2_qiJaaoQDMTdLj56tkP52iUxXg0pSb8u-S1iA0',
    signingPrivateKey: 'atlovbiCQUWv5lHkRohXluNvP69z6GXZ4dvAfBeTLUuZjmrb-qIlpqhAMxN0uPnq2Q_naJTFeDSlJvy75LWIDQ'},
  requesterDID: 'did:jlinc:iC2FSXaxH8HmK8sA0O6G3ZBVXpwb3IA_XfrYQDwnGE8'
};
const reqJWS = auth.request(validReqObject);

describe('verify request', function() {

  context('when given a valid request JWS', function(){
    const result = auth.verifyReq(reqJWS);
    it('should return a validated request object', function(){
      expect(result).to.be.an('object');
      expect(Object.keys(result)).to.have.lengthOf(6);
      expect(isTimestamp.test(result.iat)).to.be.true;
      expect(isUUID.test(result.authId)).to.be.true;
      expect(isB64.test(result.agentPublicKey)).to.be.true;
    });
  });

  context('when given an invalid request JWS', function(){
    it('should throw error', function(){
      const invalidJWS = reqJWS.slice(0,-1);
      expect(() => {
        auth.verifyReq(invalidJWS);
      }).to.throw('Invalid JWS');
    });
  });
});
