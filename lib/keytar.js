var keytar = require('../build/Release/keytar.node')

function checkRequired(val, name) {
  if (!val || val.length <= 0) {
    throw new Error(name + ' is required.');
  }
}

module.exports = {
  getPassword: function (service, account) {
    checkRequired(service, 'Service')
    checkRequired(account, 'Account')

    return keytar.getPassword(service, account)
  },

  setPassword: function (service, account, password, targetname = '', credType = -1, credPersist = -1) {
    checkRequired(service, 'Service')
    checkRequired(account, 'Account')
    checkRequired(password, 'Password')

    return keytar.setPassword(service, account, password, targetname, credType, credPersist)
  },

  deletePassword: function (service, account) {
    checkRequired(service, 'Service')
    checkRequired(account, 'Account')

    return keytar.deletePassword(service, account)
  },

  findPassword: function (service) {
    checkRequired(service, 'Service')

    return keytar.findPassword(service)
  },

  findCredentials: function (service) {
    checkRequired(service, 'Service')

    return keytar.findCredentials(service)
  }
}
