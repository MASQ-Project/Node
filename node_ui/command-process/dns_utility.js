// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (function () {
  const childProcess = require('child_process')
  const path = require('path')
  const consoleWrapper = require('../wrappers/console_wrapper')
  const sudoPrompt = require('sudo-prompt')

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
      return new Promise((resolve, reject) => resolve(null))
    }

    return runDnsUtility('revert')
  }

  function subvert () {
    let isSubverted = getStatus()
    if (isSubverted && isSubverted.indexOf('subverted') >= 0) {
      return new Promise((resolve, reject) => resolve(null))
    }

    return runDnsUtility('subvert')
  }

  function runDnsUtility (mode) {
    return new Promise((resolve, reject) => {
      sudoPrompt.exec(dnsUtilityPath + ' ' + mode, { name: 'DNS utility' }, function (error, stdout, stderr) {
        if (error || stderr) {
          consoleWrapper.log('dns_utility failed: ', stderr || error.message)
          reject(error || stderr)
        } else {
          resolve(stdout)
        }
      })
    })
  }

  return {
    getStatus: getStatus,
    revert: revert,
    subvert: subvert
  }
}())
