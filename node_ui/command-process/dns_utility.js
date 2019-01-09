// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (() => {
  const childProcess = require('child_process')
  const pathWrapper = require('../wrappers/path_wrapper')
  const consoleWrapper = require('../wrappers/console_wrapper')
  const sudoPrompt = require('sudo-prompt')

  const dnsUtilityPathRelative = '../static/binaries/dns_utility'
  const dnsUtilityPathUnquoted = pathWrapper.resolveUnquoted(__dirname, dnsUtilityPathRelative)
  const dnsUtilityPathQuoted = pathWrapper.resolveQuoted(__dirname, dnsUtilityPathRelative)

  function getStatus () {
    let status = childProcess.spawnSync(dnsUtilityPathUnquoted, ['status'])
    if (status && status.error) {
      return 'ERROR: Failed to call dns_utility inspect: ' + status.error.code
    }
    return status.stdout
  }

  function revert () {
    let isReverted = getStatus()
    if (isReverted && isReverted.indexOf('reverted') >= 0) {
      return Promise.resolve(null)
    }

    return runDnsUtility('revert')
  }

  function subvert () {
    let isSubverted = getStatus()
    if (isSubverted && isSubverted.indexOf('subverted') >= 0) {
      return Promise.resolve(null)
    }

    return runDnsUtility('subvert')
  }

  function runDnsUtility (mode) {
    return new Promise((resolve, reject) => {
      sudoPrompt.exec(dnsUtilityPathQuoted + ' ' + mode, { name: 'DNS utility' }, (error, stdout, stderr) => {
        if (error || stderr) {
          consoleWrapper.log('dns_utility failed: ', stderr || error.message)
          reject(error || new Error(stderr))
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
})()
