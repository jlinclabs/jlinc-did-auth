'use strict';

const version = require('../../package.json').version;
const auth = require('../../');

describe('did-auth', function() {
  it('should match this pattern', function(){
    expect(auth).to.matchPattern({
      version,
      JlincDidAuthError: _.isFunction,
      createNonce: _.isFunction,
      request: _.isFunction,
      verifyChallenge: _.isFunction,
      signChallenge: _.isFunction,
      verifyReq: _.isFunction,
      createChallenge: _.isFunction,
      verifyChallengeSignature: _.isFunction,
    });
  });
});
