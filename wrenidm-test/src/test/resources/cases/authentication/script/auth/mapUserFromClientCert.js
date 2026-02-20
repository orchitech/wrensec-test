/* global security, properties, openidm */
(function () {
  const _ = require('lib/lodash');

  const matchPattern = /^CN=([a-z]+)(?:,.*)?$/;
  const userNameMatch = security.authenticationId.match(matchPattern);
  const userName = userNameMatch != null ? userNameMatch[1] : null;

  if (!userName) {
    throw {
      code: 401,
      message: 'Access denied, user inactive'
    };
  }

  const managedUsers = openidm.query('managed/user', {
    _queryFilter:  `/userName eq "${userName}"`
  }, ['*', 'authzRoles']);

  if (!managedUsers.result.length) {
    throw {
      code: 401,
      message: 'Access denied, managed/user entry is not found'
    };
  }

  const managedUser = managedUsers.result[0];

  if (managedUser.accountStatus != 'active') {
    throw {
      code: 401,
      message: 'Access denied, user inactive'
    };
  }

  security.authorization = {
    id: managedUser._id,
    moduleId: security.authorization.moduleId,
    component: 'managed/user',
    roles: managedUser.authzRoles ?
      _.uniq(
        security.authorization.roles.concat(
          _.map(managedUser.authzRoles, function (role) {
            // appending empty string gets the value from java into a native JS object
            return org.forgerock.json.resource.ResourcePath.valueOf(role._ref).leaf() + '';
          })
        )
      ) : security.authorization.roles
  };

  return security;
})();
