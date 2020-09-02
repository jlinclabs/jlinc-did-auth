'use strict';

class JlincJwtError extends Error {
  constructor(message){
    super(message);
    this.name = this.constructor.name;
    Error.captureStackTrace(this, this.constructor);
  }
};

module.exports =  {
  version: require('./package.json').version,
  JlincJwtError,

  
};
