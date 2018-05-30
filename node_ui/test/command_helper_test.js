// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const td = require('testdouble')

describe('CommandHelper', function () {
  let process, nodeCmd, sudoPrompt, treeKill, subject

  beforeEach(function () {
    process = td.replace('../wrappers/process_wrapper')
    nodeCmd = td.replace('node-cmd')
    sudoPrompt = td.replace('sudo-prompt')
    treeKill = td.replace('tree-kill')

    process.platform = 'irrelevant'
    process.pid = 1234
  })

  afterEach(function () {
    td.reset()
  })

  describe('Unix Platforms', function () {
    beforeEach(function () {
      process.platform = 'linux'
      td.when(process.getuid()).thenReturn('uid')
      td.when(process.getgid()).thenReturn('gid')

      subject = require('../command-process/command_helper')
    })

    it('sets sudo environment variables', function () {
      assert.strictEqual(process.env.SUDO_UID, 'uid')
      assert.strictEqual(process.env.SUDO_GID, 'gid')
    })

    describe('starting on linux', function () {
      const command = /[/\\]static[/\\]scripts[/\\]substratum_node\.sh" uid gid ".*[/\\]static[/\\]binaries[/\\]linux[/\\]SubstratumNode" --dns_servers \d.*/

      beforeEach(function () {
        process.platform = 'linux'
        subject = require('../command-process/command_helper')

        subject.startSubstratumNode('callback')
      })

      it('executes the command via sudo prompt', function () {
        td.verify(sudoPrompt.exec(td.matchers.contains(command), { name: 'Substratum Node' }, 'callback'))
      })
    })

    describe('starting on mac', function () {
      const command = /[/\\]static[/\\]scripts[/\\]substratum_node\.sh" uid gid ".*[/\\]static[/\\]binaries[/\\]mac[/\\]SubstratumNode" --dns_servers \d.*/

      beforeEach(function () {
        process.platform = 'darwin'
        subject = require('../command-process/command_helper')

        subject.startSubstratumNode('callback')
      })

      it('executes the command via sudo prompt', function () {
        td.verify(sudoPrompt.exec(td.matchers.contains(command), { name: 'Substratum Node' }, 'callback'))
      })
    })

    describe('stopping', function () {
      describe('successfully', function () {
        var error
        var wasCalled

        beforeEach(function () {
          wasCalled = false

          subject.stopSubstratumNode(function (e) {
            error = e
            wasCalled = true
          })
        })

        it('kills the process', function () {
          td.verify(process.kill(-1234))
        })

        it('executes the callback', function () {
          assert.strictEqual(wasCalled, true)
          assert.strictEqual(error, undefined)
        })
      })

      describe('sends back an error if encountered', function () {
        var error
        var wasCalled

        beforeEach(function () {
          wasCalled = false
          td.when(process.kill(-1234)).thenThrow(new Error('whoa!'))

          subject.stopSubstratumNode(function (e) {
            error = e
            wasCalled = true
          })
        })

        it('executes the callback', function () {
          assert.strictEqual(wasCalled, true)
          assert.strictEqual(error, 'whoa!')
        })
      })
    })
  })

  describe('Windows Platform', function () {
    beforeEach(function () {
      process.platform = 'win32'

      subject = require('../command-process/command_helper')
    })

    describe('starting', function () {
      const command = /[/\\]static[/\\]scripts[/\\]substratum_node\.cmd" ".*[/\\]static[/\\]binaries[/\\]win[/\\]SubstratumNode" --dns_servers \d.*/

      beforeEach(function () {
        subject.startSubstratumNode('callback')
      })

      it('executes the command via node cmd', function () {
        td.verify(nodeCmd.get(td.matchers.contains(command), 'callback'))
      })
    })

    describe('stopping', function () {
      beforeEach(function () {
        subject.stopSubstratumNode('callback')
      })

      it('kills the process', function () {
        td.verify(treeKill(1234, 'callback'))
      })
    })
  })
})
