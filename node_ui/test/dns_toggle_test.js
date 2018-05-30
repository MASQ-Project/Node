// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const td = require('testdouble')

describe('DnsToggler', function () {
  var mockConsole, sudoPrompt, subject, command
  var mockDnsToggle, mockDnsStatus

  beforeEach(function () {
    mockConsole = td.replace('../wrappers/console_wrapper')
    sudoPrompt = td.replace('sudo-prompt')
    mockDnsToggle = {}
    mockDnsStatus = {}

    subject = require('../render-process/dns_toggle')
    subject.bindEvents(mockDnsToggle, mockDnsStatus)
  })

  afterEach(function () {
    td.reset()
  })

  describe('subverting DNS', function () {
    beforeEach(function () {
      command = /[/\\]static[/\\]binaries[/\\]dns_utility" subvert/

      mockDnsToggle.checked = true // simulate the click changing the state (because the mock doesn't do this automatically like a DOM element would)
      mockDnsToggle.onclick()
    })

    it('calls dns_utility to subvert', function () {
      td.verify(sudoPrompt.exec(td.matchers.contains(command), { name: 'DNS utility' }, td.matchers.anything()))
    })

    describe('receives error from dns_utility', function () {
      beforeEach(function () {
        var error = {message: 'blablabla'}
        var stdout = false
        var stderr = false
        td.when(sudoPrompt.exec(td.matchers.anything(), td.matchers.anything())).thenCallback(error, stdout, stderr)
        mockDnsToggle.onclick()
      })

      it('logs to the console', function () {
        td.verify(mockConsole.log('dns_utility failed: ', 'blablabla'))
      })

      it('unchecks the toggle', function () {
        assert.strictEqual(mockDnsToggle.checked, false)
      })

      it('updates the status', function () {
        assert.strictEqual(mockDnsStatus.innerText, 'Serving')
      })
    })

    describe('receives stderr from dns_utility', function () {
      beforeEach(function () {
        var error = false
        var stdout = false
        var stderr = 'blablabla'
        td.when(sudoPrompt.exec(td.matchers.anything(), td.matchers.anything())).thenCallback(error, stdout, stderr)
        mockDnsToggle.onclick()
      })

      it('logs to console', function () {
        td.verify(mockConsole.log('dns_utility failed: ', 'blablabla'))
      })

      it('unchecks the toggle', function () {
        assert.strictEqual(mockDnsToggle.checked, false)
      })

      it('updates the status', function () {
        assert.strictEqual(mockDnsStatus.innerText, 'Serving')
      })
    })

    describe('receiving no errors from dns_utility', function () {
      beforeEach(function () {
        var error = false
        var stderr = false
        var stdout = true
        td.when(sudoPrompt.exec(td.matchers.anything(), td.matchers.anything())).thenCallback(error, stdout, stderr)
        mockDnsToggle.onclick()
      })

      it('checks the toggle', function () {
        assert.strictEqual(mockDnsToggle.checked, true)
      })

      it('updates the status', function () {
        assert.strictEqual(mockDnsStatus.innerText, 'Consuming')
      })
    })
  })

  describe('reverting DNS', function () {
    beforeEach(function () {
      command = /[/\\]static[/\\]binaries[/\\]dns_utility" revert/

      mockDnsToggle.checked = false // simulate the click changing the state (because the mock doesn't do this automatically like a DOM element would)
      mockDnsToggle.onclick()
    })

    it('calls dns_utility to revert', function () {
      td.verify(sudoPrompt.exec(td.matchers.contains(command), { name: 'DNS utility' }, td.matchers.anything()))
    })

    describe('receives error from dns_utility', function () {
      beforeEach(function () {
        var error = {message: 'blablabla'}
        var stdout = false
        var stderr = false
        td.when(sudoPrompt.exec(td.matchers.anything(), td.matchers.anything())).thenCallback(error, stdout, stderr)
        mockDnsToggle.onclick()
      })

      it('logs to the console', function () {
        td.verify(mockConsole.log('dns_utility failed: ', 'blablabla'))
      })

      it('checks the toggle', function () {
        assert.strictEqual(mockDnsToggle.checked, true)
      })

      it('updates the status', function () {
        assert.strictEqual(mockDnsStatus.innerText, 'Consuming')
      })
    })

    describe('receives stderr from dns_utility', function () {
      beforeEach(function () {
        var error = false
        var stdout = false
        var stderr = 'blablabla'
        td.when(sudoPrompt.exec(td.matchers.anything(), td.matchers.anything())).thenCallback(error, stdout, stderr)
        mockDnsToggle.onclick()
      })

      it('logs to console', function () {
        td.verify(mockConsole.log('dns_utility failed: ', 'blablabla'))
      })

      it('unchecks the toggle', function () {
        assert.strictEqual(mockDnsToggle.checked, true)
      })

      it('updates the status', function () {
        assert.strictEqual(mockDnsStatus.innerText, 'Consuming')
      })
    })

    describe('receiving no errors from dns_utility', function () {
      beforeEach(function () {
        var error = false
        var stderr = false
        var stdout = true
        td.when(sudoPrompt.exec(td.matchers.anything(), td.matchers.anything())).thenCallback(error, stdout, stderr)
        mockDnsToggle.onclick()
      })

      it('unchecks the toggle', function () {
        assert.strictEqual(mockDnsToggle.checked, false)
      })

      it('updates the status', function () {
        assert.strictEqual(mockDnsStatus.innerText, 'Serving')
      })
    })
  })

  describe('has initial state', function () {
    it('is not checked', function () {
      assert.strictEqual(mockDnsToggle.checked, false)
    })

    it('shows status text for not being subverted', function () {
      assert.strictEqual(mockDnsStatus.innerText, 'Serving')
    })
  })
})
