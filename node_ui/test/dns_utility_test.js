// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const td = require('testdouble')
const path = require('path')

describe('DNS Utility', () => {
  let subject
  let childProcess
  let sudoPrompt
  let result
  let mockConsole

  let dnsUtilityPath = path.resolve(__dirname, '.', '../static/binaries/dns_utility')
  let dnsUtilityPathQuoted = '"' + dnsUtilityPath + '"'
  let dnsUtilityArgs = ['status']

  beforeEach(() => {
    childProcess = td.replace('child_process')
    sudoPrompt = td.replace('sudo-prompt')
    mockConsole = td.replace('../wrappers/console_wrapper')

    subject = require('../command-process/dns_utility')
  })

  afterEach(() => {
    td.reset()
  })

  describe('getStatus', () => {
    describe('for subverted', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'subverted'})

        result = subject.getStatus()
      })

      it('returns subverted', () => {
        assert.equal('subverted', result)
      })
    })

    describe('for reverted', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'reverted'})

        result = subject.getStatus()
      })

      it('returns reverted', () => {
        assert.equal('reverted', result)
      })
    })

    describe('for error', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({error: {code: 'ENOENT'}})

        result = subject.getStatus()
      })

      it('returns ERROR ', () => {
        assert('ERROR: Failed to call inspect: ENOENT', result)
      })
    })
  })

  describe('revert', () => {
    describe('for not subverted', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'reverted'})
        subject.revert()
      })

      it('should not call dns_utility command', () => {
        td.verify(sudoPrompt.exec(td.matchers.anything(), td.matchers.anything, td.matchers.anything), {times: 0})
      })
    })

    describe('for subverted ', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'subverted'})
        subject.revert()
      })

      it('should call dns_utility command', () => {
        td.verify(sudoPrompt.exec(dnsUtilityPathQuoted + ' revert', {name: 'DNS utility'}, td.matchers.anything()), {times: 1})
      })
    })

    describe('error', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'subverted'})

        let error = {message: 'failed to revert'}
        let stdout = null
        let stderr = null

        td.when(sudoPrompt.exec(dnsUtilityPathQuoted + ' revert', {name: 'DNS utility'})).thenCallback(error, stdout, stderr)
        subject.revert().catch((reason) => {
          assert.strictEqual(reason.message, error.message)
        })
      })

      it('logs error message', () => {
        td.verify(mockConsole.log('dns_utility failed: ', 'failed to revert'))
      })
    })

    describe('stderr', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'subverted'})

        let error = null
        let stdout = null
        let stderr = 'failed to revert'

        td.when(sudoPrompt.exec(dnsUtilityPathQuoted + ' revert', {name: 'DNS utility'})).thenCallback(error, stdout, stderr)
        subject.revert().catch((reason) => {
          assert.strictEqual(reason.message, stderr)
        })
      })

      it('logs stderr message', () => {
        td.verify(mockConsole.log('dns_utility failed: ', 'failed to revert'))
      })
    })
  })

  describe('subvert', () => {
    describe('for reverted', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'subverted'})
        subject.subvert()
      })

      it('should not call dns_utility command', () => {
        td.verify(sudoPrompt.exec(td.matchers.anything(), td.matchers.anything(), td.matchers.anything()), {times: 0})
      })
    })

    describe('for subverted', () => {
      beforeEach(() => {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'reverted'})
        subject.subvert()
      })

      it('should call dns_utility command', () => {
        td.verify(sudoPrompt.exec(dnsUtilityPathQuoted + ' subvert', {name: 'DNS utility'}, td.matchers.anything()), {times: 1})
      })
    })
  })
})
