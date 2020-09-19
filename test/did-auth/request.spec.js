'use strict';

const auth = require('jlinc-did-auth');
const jwt = require('jlinc-jwt');
const isJWT = /^[\w-]+\.[\w-]+\.[\w-]+$/;
const isTimestamp = /^[\d]{10,13}$/; //with or without milliseconds
const isUUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12}$/; //v4 UUID
const validReqObject = {
  agentAuthReqURL: 'http://localhost:8080',
  agentDID: 'did:jlinc:mY5q2_qiJaaoQDMTdLj56tkP52iUxXg0pSb8u-S1iA0',
  agentSigningKeys: {signingPublicKey: 'mY5q2_qiJaaoQDMTdLj56tkP52iUxXg0pSb8u-S1iA0',
    signingPrivateKey: 'atlovbiCQUWv5lHkRohXluNvP69z6GXZ4dvAfBeTLUuZjmrb-qIlpqhAMxN0uPnq2Q_naJTFeDSlJvy75LWIDQ'},
  requesterDID: 'did:jlinc:iC2FSXaxH8HmK8sA0O6G3ZBVXpwb3IA_XfrYQDwnGE8'
};

describe('request', function() {

  context('when given a valid reqObject', function(){
    const result = auth.request(validReqObject);
    it('should return a verifiable JWT', function(){
      expect(isJWT.test(result)).to.be.true;
      const verified = jwt.verifyEdDsa(result);
      expect(verified).to.be.an('object');
      expect(Object.keys(verified.payload)).to.have.lengthOf(5);
      expect(isTimestamp.test(verified.payload.iat)).to.be.true;
      expect(isUUID.test(verified.payload.authId)).to.be.true;
    });
  });

  context('when given an invalid agent DID', function(){
    it('should throw error', function(){
      const invalidAgentDid = Object.assign({}, validReqObject);
      invalidAgentDid.agentDID = 'not:a:DID';
      expect(() => {
        auth.request(invalidAgentDid);
      }).to.throw('RequestError: agentDID not a valid DID');
    });
  });

  context('when given an invalid requester DID', function(){
    it('should throw error', function(){
      const invalidRequesterDid = Object.assign({}, validReqObject);
      invalidRequesterDid.requesterDID = 'not:a:DID';
      expect(() => {
        auth.request(invalidRequesterDid);
      }).to.throw('RequestError: requesterDID not a valid DID');
    });
  });
});
