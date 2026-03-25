(function(){
  if (request.method !== 'query' || request.resourcePath !== 'users') {
      throw { code: 400, message : 'Invalid request.' };
  }
  return openidm.query('managed/user', { _queryFilter: '/userName eq "endpoint"' });
})();
