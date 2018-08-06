// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const td = require('testdouble')
const path = require('path')

describe('DNS Utility', function () {
  let subject
  let childProcess
  let sudoPrompt
  let result
  let mockConsole
  let mockStatusHandler

  let dnsUtilityPath = path.resolve(__dirname, '.', '../static/binaries/dns_utility')
  let dnsUtilityArgs = ['status']

  beforeEach(function () {
    childProcess = td.replace('child_process')
    sudoPrompt = td.replace('sudo-prompt')
    mockConsole = td.replace('../wrappers/console_wrapper')
    mockStatusHandler = td.replace('../handlers/status_handler')

    subject = require('../command-process/dns_utility')
  })

  afterEach(function () {
    td.reset()
  })

  describe('getStatus', function () {
    describe('for subverted', function () {
      beforeEach(function () {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'subverted'})

        result = subject.getStatus()
      })

      it('returns subverted', function () {
        assert.equal('subverted', result)
      })
    })

    describe('for reverted', function () {
      beforeEach(function () {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'reverted'})

        result = subject.getStatus()
      })

      it('returns reverted', function () {
        assert.equal('reverted', result)
      })
    })

    describe('for error', function () {
      beforeEach(function () {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({error: {code: 'ENOENT'}})

        result = subject.getStatus()
      })

      it('returns ERROR ', function () {
        assert('ERROR: Failed to call inspect: ENOENT', result)
      })
    })
  })

  describe('revert', function () {
    describe('for not subverted', function () {
      beforeEach(function () {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'reverted'})
        subject.revert()
      })

      it('should not call dns_utility command', function () {
        td.verify(sudoPrompt.exec(td.matchers.anything(), td.matchers.anything, td.matchers.anything), {times: 0})
      })
    })

    describe('for subverted ', function () {
      beforeEach(function () {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'subverted'})
        subject.revert()
      })

      it('should call dns_utility command', function () {
        td.verify(sudoPrompt.exec(dnsUtilityPath + ' revert', {name: 'DNS utility'}, td.matchers.anything()), {times: 1})
      })
    })

    describe('error', function () {
      beforeEach(function () {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'subverted'})

        let error = {message: 'failed to revert'}
        let stdout = null
        let stderr = null

        td.when(sudoPrompt.exec(dnsUtilityPath + ' revert', {name: 'DNS utility'})).thenCallback(error, stdout, stderr)
        subject.revert()
      })

      it('logs error message', function () {
        td.verify(mockConsole.log('dns_utility failed: ', 'failed to revert'))
      })

      it('sends invalid state', function () {
        td.verify(mockStatusHandler.emit('invalid'), { times: 1 })
      })
    })

    describe('stderr', function () {
      beforeEach(function () {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'subverted'})

        let error = null
        let stdout = null
        let stderr = 'failed to revert'

        td.when(sudoPrompt.exec(dnsUtilityPath + ' revert', {name: 'DNS utility'})).thenCallback(error, stdout, stderr)
        subject.revert()
      })

      it('logs stderr message', function () {
        td.verify(mockConsole.log('dns_utility failed: ', 'failed to revert'))
      })

      it('sends invalid state', function () {
        td.verify(mockStatusHandler.emit('invalid'), { times: 1 })
      })
    })
  })

  describe('subvert', function () {
    describe('for reverted', function () {
      beforeEach(function () {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'subverted'})
        subject.subvert()
      })

      it('should not call dns_utility command', function () {
        td.verify(sudoPrompt.exec(td.matchers.anything(), td.matchers.anything(), td.matchers.anything()), {times: 0})
      })
    })

    describe('for subverted', function () {
      beforeEach(function () {
        td.when(childProcess.spawnSync(dnsUtilityPath, dnsUtilityArgs)).thenReturn({stdout: 'reverted'})
        subject.subvert()
      })

      it('should call dns_utility command', function () {
        td.verify(sudoPrompt.exec(dnsUtilityPath + ' subvert', {name: 'DNS utility'}, td.matchers.anything()), {times: 1})
      })
    })
  })
})
