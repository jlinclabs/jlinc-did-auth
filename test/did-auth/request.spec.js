'use strict';

const jwt = require('@jlinc/jwt');
const { generateRequest } = require('../helpers');
const auth = require('../../');

describe('request', function() {

  let request;
  beforeEach(function() {
    ({ request } = generateRequest());
  });

  context('when given a valid reqObject', function(){
    it('should return a verifiable JWT', function(){
      const resultJWT = auth.request(request);
      expect(resultJWT).to.be.aJWT();
      const result = jwt.verifyEdDsa(resultJWT);
      expect(result).to.matchPattern({
        signed: _.isString,
        signature: _.isString,
        header: {
          alg: 'EdDSA',
          typ: 'JWT',
          jwk: {
            kty: 'OKP',
            crv: 'Ed25519',
            x: request.agentSigningKeys.signingPublicKey,
            kid: request.agentDID,
          },
        },
        payload: {
          agentAuthReqURL: request.agentAuthReqURL,
          agentDID: request.agentDID,
          requesterDID: request.requesterDID,
          iat: _.isIAT,
          authId: _.isUUIDv4,
        },
      });
    });
  });

  context('when given an invalid agent DID', function(){
    it('should throw error', function(){
      expect(() => {
        auth.request({
          ...request,
          agentDID: 'not:a:DID',
        });
      }).to.throw('RequestError: agentDID not a valid DID');
    });
  });

  context('when given an invalid requester DID', function(){
    it('should throw error', function(){
      expect(() => {
        auth.request({
          ...request,
          requesterDID: 'not:a:DID',
        });
      }).to.throw('RequestError: requesterDID not a valid DID');
    });
  });
});
