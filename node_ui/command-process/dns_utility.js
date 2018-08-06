// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (function () {
  const childProcess = require('child_process')
  const path = require('path')
  const consoleWrapper = require('../wrappers/console_wrapper')
  const sudoPrompt = require('sudo-prompt')
  const statusHandler = require('../handlers/status_handler')

  let dnsUtilityPath = path.resolve(__dirname, '.', '../static/binaries/dns_utility')

  function getStatus () {
    let status = childProcess.spawnSync(dnsUtilityPath, ['status'])
    if (status && status.error) {
      return 'ERROR: Failed to call dns_utility inspect: ' + status.error.code
    }
    return status.stdout
  }

  function revert () {
    let isReverted = getStatus()
    if (isReverted && isReverted.indexOf('reverted') >= 0) {
      return
    }

    runDnsUtility('revert', function () { statusHandler.emit('invalid') })
  }

  function subvert () {
    let isSubverted = getStatus()
    if (isSubverted && isSubverted.indexOf('subverted') >= 0) {
      return
    }

    runDnsUtility('subvert')
  }

  function runDnsUtility (mode, errorCallback) {
    sudoPrompt.exec(dnsUtilityPath + ' ' + mode, { name: 'DNS utility' }, function (error, stdout, stderr) {
      if (error || stderr) {
        consoleWrapper.log('dns_utility failed: ', stderr || error.message)
        errorCallback()
      }
    })
  }

  return {
    getStatus: getStatus,
    revert: revert,
    subvert: subvert
  }
})()
