// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (function () {
  const ps = require('ps-list')
  const treeKill = require('tree-kill')

  function killByName (processName) {
    ps().then((list) => {
      list.filter(row => row.name.indexOf(processName) >= 0).forEach(item => treeKill(item.pid))
    })
  }

  function findByName (processName, callback) {
    ps().then(function (list) {
      callback(list.filter(row => row.name.indexOf(processName) >= 0))
    })
  }

  return {
    killByName: killByName,
    findByName: findByName
  }
}())
