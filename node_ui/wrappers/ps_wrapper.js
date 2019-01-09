// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (() => {
  const ps = require('../command-process/ps')
  const treeKill = require('tree-kill')
  const path = require('path')

  function killNodeProcess () {
    ps().then((list) => {
      list.filter(row =>
        (row.name.indexOf('SubstratumNode') >= 0 && row.cmd.indexOf('static' + path.sep + 'binaries') >= 0)
      ).forEach(item => treeKill(item.pid))
    })
  }

  function findNodeProcess (callback) {
    ps().then(function (list) {
      callback(list.filter(row =>
        (row.name.indexOf('SubstratumNode') >= 0 && row.cmd.indexOf('static' + path.sep + 'binaries') >= 0)
      ))
    })
  }

  return {
    killNodeProcess: killNodeProcess,
    findNodeProcess: findNodeProcess
  }
})()
