// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const td = require('testdouble')
const assert = require('assert')
const {EventEmitter} = require('events')

describe('NodeActuator', function () {
  let mockChildProcess
  let mockSudoPrompt
  let mockConsole

  let mockNodeStatusLabel
  let mockNodeStatusButtonOff
  let mockNodeStatusButtonServing
  let mockNodeStatusButtonConsuming

  let mockSubstratumNodeProcess

  let subject

  beforeEach(function () {
    mockChildProcess = td.replace('child_process')
    mockSudoPrompt = td.replace('sudo-prompt')
    mockConsole = td.replace('../wrappers/console_wrapper')

    mockNodeStatusLabel = { innerHTML: 'Off' }
    mockNodeStatusButtonOff = createMockButton('button-active')
    mockNodeStatusButtonServing = createMockButton()
    mockNodeStatusButtonConsuming = createMockButton()

    mockSubstratumNodeProcess = new EventEmitter()
    mockSubstratumNodeProcess.send = td.function()
    td.when(mockSudoPrompt.exec(td.matchers.anything(), td.matchers.anything()))
      .thenCallback(false, 'success!', false)
    td.when(mockChildProcess.fork(td.matchers.contains('substratum_node.js'), [], {
      silent: true,
      stdio: [0, 1, 2, 'ipc'],
      detached: true
    })).thenReturn(mockSubstratumNodeProcess)

    subject = require('../render-process/node_actuator')
    subject.bind(mockNodeStatusLabel, mockNodeStatusButtonOff, mockNodeStatusButtonServing, mockNodeStatusButtonConsuming)
  })

  afterEach(function () {
    td.reset()
  })

  describe('off', function () {
    beforeEach(function () {
      mockNodeStatusButtonOff.onclick()
    })

    it('does nothing', function () {
      assertStatus('off')
      assertDNSNotSubverted()
      assertNodeNotStopped()
    })

    describe('to off', function () {
      beforeEach(function () {
        mockNodeStatusButtonOff.onclick()
      })

      it('does nothing', function () {
        assertStatus('off')
        assertDNSNotSubverted()
        assertNodeStarted(0)
      })
    })

    describe('to serving', function () {
      beforeEach(function () {
        mockNodeStatusButtonServing.onclick()
      })

      it('sets the status to serving', function () {
        assertStatus('serving')
      })

      it('does not revert the dns', function () {
        assertDNSNotReverted()
      })

      it('starts the node', function () {
        assertNodeStarted()
      })
    })

    describe('to consuming', function () {
      beforeEach(function () {
        mockNodeStatusButtonConsuming.onclick()
      })

      it('sets the status to consuming', function () {
        assertStatus('consuming')
      })

      it('subverts the dns', function () {
        assertDNSSubverted()
      })

      it('starts the node', function () {
        assertNodeStarted()
      })
    })
  })

  describe('serving', function () {
    beforeEach(function () {
      mockNodeStatusButtonServing.onclick()
    })

    it('sets the status to serving', function () {
      assertStatus('serving')
    })

    it('does not revert the dns', function () {
      assertDNSNotReverted()
    })

    it('starts the node', function () {
      assertNodeStarted()
    })

    describe('to off', function () {
      beforeEach(function () {
        mockNodeStatusButtonOff.onclick()
      })

      it('sets the status to off', function () {
        assertStatus('off')
      })

      it('does not revert dns', function () {
        assertDNSNotReverted()
      })

      it('stops the node', function () {
        assertNodeStopped()
      })
    })

    describe('to serving', function () {
      beforeEach(function () {
        mockNodeStatusButtonServing.onclick()
      })

      it('does not try to start node again', function () {
        assertStatus('serving')
        assertDNSNotSubverted()
        assertNodeStarted()
      })
    })

    describe('to consuming', function () {
      beforeEach(function () {
        mockNodeStatusButtonConsuming.onclick()
      })

      it('sets the status to consuming', function () {
        assertStatus('consuming')
      })

      it('does not start the node', function () {
        assertNodeStarted()
      })

      it('subverts dns', function () {
        assertDNSSubverted()
      })
    })
  })

  describe('consuming', function () {
    beforeEach(function () {
      mockNodeStatusButtonConsuming.onclick()
    })

    it('sets the status to consuming', function () {
      assertStatus('consuming')
    })

    it('subverts dns', function () {
      assertDNSSubverted()
    })

    it('starts the node', function () {
      assertNodeStarted()
    })

    describe('to off', function () {
      beforeEach(function () {
        mockNodeStatusButtonOff.onclick()
      })

      it('sets the status to off', function () {
        assertStatus('off')
      })

      it('reverts the dns', function () {
        assertDNSReverted()
      })

      it('stops the node', function () {
        assertNodeStopped()
      })
    })

    describe('to serving', function () {
      beforeEach(function () {
        mockNodeStatusButtonServing.onclick()
      })

      it('sets the status to serving', function () {
        assertStatus('serving')
      })

      it('does not start the node', function () {
        assertNodeStarted()
      })

      it('reverts the dns', function () {
        assertDNSReverted()
      })
    })

    describe('to consuming', function () {
      beforeEach(function () {
        mockNodeStatusButtonConsuming.onclick()
      })

      it('does nothing', function () {
        assertStatus('consuming')
        assertDNSNotReverted()
        assertNodeStarted()
      })
    })
  })

  describe('childProcess messages', function () {
    beforeEach(function () {
      mockNodeStatusButtonServing.onclick()
    })

    describe('receiving a message from child process', function () {
      beforeEach(function () {
        mockSubstratumNodeProcess.emit('message', 'blooga')
      })

      it('logs the message', function () {
        td.verify(mockConsole.log('substratum_node process received message: ', 'blooga'))
      })

      it('does not update the status', function () {
        assertStatus('serving')
      })
    })

    describe('receiving an error message from child process', function () {
      describe('while serving', function () {
        beforeEach(function () {
          mockNodeStatusButtonServing.onclick()

          mockSubstratumNodeProcess.emit('message', 'Command returned error: blooga')
        })

        it('logs the error', function () {
          td.verify(mockConsole.log('substratum_node process received message: ', 'Command returned error: blooga'))
        })

        it('updates the status', function () {
          assertStatus('off')
        })
      })

      describe('while consuming', function () {
        describe('dns revert succeeds', function () {
          beforeEach(function () {
            mockNodeStatusButtonConsuming.onclick()

            mockSubstratumNodeProcess.emit('message', 'Command returned error: blooga')
          })

          it('reverts the dns', function () {
            assertDNSReverted()
          })

          it('logs the error', function () {
            td.verify(mockConsole.log('substratum_node process received message: ', 'Command returned error: blooga'))
          })

          it('updates the status', function () {
            assertStatus('off')
          })
        })

        describe('dns revert fails', function () {
          beforeEach(function () {
            mockNodeStatusButtonConsuming.onclick()

            let error = { message: 'blablabla' }
            let stdout = false
            let stderr = false
            td.when(mockSudoPrompt.exec(td.matchers.anything(), td.matchers.anything()))
              .thenCallback(error, stdout, stderr)

            mockSubstratumNodeProcess.emit('message', 'Command returned error: blooga')
          })

          it('tries to revert the dns', function () {
            assertDNSReverted()
          })

          it('logs the error', function () {
            td.verify(mockConsole.log('substratum_node process received message: ', 'Command returned error: blooga'))
          })

          it('updates the status', function () {
            assertStatus('invalid')
          })
        })
      })
    })

    describe('receiving error from child process', function () {
      describe('while serving', function () {
        beforeEach(function () {
          mockNodeStatusButtonServing.onclick()

          mockSubstratumNodeProcess.emit('error', new Error('blooga'))
        })

        it('logs the error', function () {
          td.verify(mockConsole.log('substratum_node process received error: ', 'blooga'))
        })

        it('updates the status', function () {
          assertStatus('off')
        })
      })

      describe('while consuming', function () {
        describe('dns revert succeeds', function () {
          beforeEach(function () {
            mockNodeStatusButtonConsuming.onclick()

            mockSubstratumNodeProcess.emit('error', new Error('blooga'))
          })

          it('reverts the dns', function () {
            assertDNSReverted()
          })

          it('logs the error', function () {
            td.verify(mockConsole.log('substratum_node process received error: ', 'blooga'))
          })

          it('updates the status', function () {
            assertStatus('off')
          })
        })

        describe('dns revert fails', function () {
          beforeEach(function () {
            mockNodeStatusButtonConsuming.onclick()

            let error = { message: 'blablabla' }
            let stdout = false
            let stderr = false
            td.when(mockSudoPrompt.exec(td.matchers.anything(), td.matchers.anything()))
              .thenCallback(error, stdout, stderr)

            mockSubstratumNodeProcess.emit('error', new Error('blooga'))
          })

          it('tries to revert the dns', function () {
            assertDNSReverted()
          })

          it('logs the error', function () {
            td.verify(mockConsole.log('substratum_node process received error: ', 'blooga'))
          })

          it('updates the status', function () {
            assertStatus('invalid')
          })
        })
      })
    })

    describe('receiving exit from child process', function () {
      describe('while serving', function () {
        beforeEach(function () {
          mockNodeStatusButtonServing.onclick()

          let error = { message: 'blablabla' }
          let stdout = false
          let stderr = false
          td.when(mockSudoPrompt.exec(td.matchers.anything(), td.matchers.anything()))
            .thenCallback(error, stdout, stderr)

          mockSubstratumNodeProcess.emit('exit', 7)
        })

        it('logs to console', function () {
          td.verify(mockConsole.log('substratum_node process exited with code ', 7))
        })

        it('does not revert DNS', function () {
          assertDNSNotReverted()
        })

        it('updates the status', function () {
          assertStatus('off')
        })
      })

      describe('while consuming', function () {
        describe('dns revert succeeds', function () {
          beforeEach(function () {
            mockNodeStatusButtonConsuming.onclick()

            mockSubstratumNodeProcess.emit('exit', 7)
          })

          it('logs to console', function () {
            td.verify(mockConsole.log('substratum_node process exited with code ', 7))
          })

          it('reverts DNS', function () {
            assertDNSReverted()
          })

          it('updates the status', function () {
            assertStatus('off')
          })
        })

        describe('dns revert fails', function () {
          beforeEach(function () {
            mockNodeStatusButtonConsuming.onclick()

            let error = { message: 'blablabla' }
            let stdout = false
            let stderr = false
            td.when(mockSudoPrompt.exec(td.matchers.anything(), td.matchers.anything()))
              .thenCallback(error, stdout, stderr)

            mockSubstratumNodeProcess.emit('exit', 7)
          })

          it('logs to console', function () {
            td.verify(mockConsole.log('substratum_node process exited with code ', 7))
          })

          it('tries to revert DNS', function () {
            assertDNSReverted()
          })

          it('updates the status', function () {
            assertStatus('invalid')
          })
        })
      })
    })
  })

  describe('dns utility errors', function () {
    describe('failing to subvert', function () {
      describe('from serving', function () {
        beforeEach(function () {
          mockNodeStatusButtonServing.onclick()
        })

        describe('receives error from dns_utility', function () {
          beforeEach(function () {
            let error = { message: 'blablabla' }
            let stdout = false
            let stderr = false
            td.when(mockSudoPrompt.exec(td.matchers.anything(), td.matchers.anything()))
              .thenCallback(error, stdout, stderr)

            mockNodeStatusButtonConsuming.onclick()
          })

          it('logs to the console', function () {
            td.verify(mockConsole.log('dns_utility failed: ', 'blablabla'))
          })

          it('should still be serving', function () {
            assertStatus('serving')
          })
        })

        describe('receives stderr from dns_utility', function () {
          beforeEach(function () {
            let error = false
            let stdout = false
            let stderr = 'blablabla'
            td.when(mockSudoPrompt.exec(td.matchers.contains('subvert'), { name: 'DNS utility' }))
              .thenCallback(error, stdout, stderr)

            mockNodeStatusButtonConsuming.onclick()
          })

          it('logs to console', function () {
            td.verify(mockConsole.log('dns_utility failed: ', 'blablabla'))
          })

          it('should still be serving', function () {
            assertStatus('serving')
          })
        })
      })

      describe('from off', function () {
        beforeEach(function () {
          mockNodeStatusButtonOff.onclick()
        })

        describe('receives error from dns_utility', function () {
          beforeEach(function () {
            let error = { message: 'blablabla' }
            let stdout = false
            let stderr = false
            td.when(mockSudoPrompt.exec(td.matchers.contains('subvert'), { name: 'DNS utility' }))
              .thenCallback(error, stdout, stderr)

            mockNodeStatusButtonConsuming.onclick()
          })

          it('logs to the console', function () {
            td.verify(mockConsole.log('dns_utility failed: ', 'blablabla'))
          })

          it('should still be off', function () {
            assertStatus('off')
          })

          it('does not start the node', function () {
            assertNodeStarted(0)
          })
        })

        describe('receives stderr from dns_utility', function () {
          beforeEach(function () {
            let error = false
            let stdout = false
            let stderr = 'blablabla'
            td.when(mockSudoPrompt.exec(td.matchers.contains('subvert'), { name: 'DNS utility' }))
              .thenCallback(error, stdout, stderr)

            mockNodeStatusButtonConsuming.onclick()
          })

          it('logs to console', function () {
            td.verify(mockConsole.log('dns_utility failed: ', 'blablabla'))
          })

          it('should still be off', function () {
            assertStatus('off')
          })

          it('does not start the node', function () {
            assertNodeStarted(0)
          })
        })
      })
    })

    describe('failing to revert', function () {
      beforeEach(function () {
        mockNodeStatusButtonConsuming.onclick()
      })

      describe('receives error from dns_utility', function () {
        beforeEach(function () {
          let error = { message: 'blablabla' }
          let stdout = false
          let stderr = false
          td.when(mockSudoPrompt.exec(td.matchers.contains('revert'), { name: 'DNS utility' }))
            .thenCallback(error, stdout, stderr)

          mockNodeStatusButtonOff.onclick()
        })

        it('logs to the console', function () {
          td.verify(mockConsole.log('dns_utility failed: ', 'blablabla'))
        })

        it('does not update the status', function () {
          assertStatus('consuming')
        })
      })

      describe('receives stderr from dns_utility', function () {
        beforeEach(function () {
          let error = false
          let stdout = false
          let stderr = 'blablabla'
          td.when(mockSudoPrompt.exec(td.matchers.contains('revert'), { name: 'DNS utility' }))
            .thenCallback(error, stdout, stderr)

          mockNodeStatusButtonServing.onclick()
        })

        it('logs to console', function () {
          td.verify(mockConsole.log('dns_utility failed: ', 'blablabla'))
        })

        it('does not update the status', function () {
          assertStatus('consuming')
        })
      })
    })
  })

  describe('shutdown', function () {
    describe('from off', function () {
      beforeEach(function () {
        mockNodeStatusButtonOff.onclick()

        subject.shutdown()
      })

      it('does not try to revert', function () {
        assertDNSNotReverted()
      })

      it('does not try to stop the node', function () {
        assertNodeNotStopped()
      })
    })

    describe('from serving', function () {
      beforeEach(function () {
        mockNodeStatusButtonServing.onclick()

        subject.shutdown()
      })

      it('does not try to revert', function () {
        assertDNSNotReverted()
      })

      it('stops the node', function () {
        assertNodeStopped()
      })
    })

    describe('from consuming', function () {
      beforeEach(function () {
        mockNodeStatusButtonConsuming.onclick()

        subject.shutdown()
      })

      it('reverts the dns', function () {
        assertDNSReverted()
      })

      it('stops the node', function () {
        assertNodeStopped()
      })
    })

    describe('from invalid', function () {
      beforeEach(function () {
        becomeInvalid()

        subject.shutdown()
      })

      it('reverts the dns', function () {
        assertDNSReverted()
      })

      it('stops the node', function () {
        assertNodeStopped()
      })
    })
  })

  function becomeInvalid () {
    mockNodeStatusButtonConsuming.onclick()

    let error = { message: 'blablabla' }
    let stdout = false
    let stderr = false
    td.when(mockSudoPrompt.exec(td.matchers.contains('revert'), { name: 'DNS utility' }))
      .thenCallback(error, stdout, stderr)

    mockNodeStatusButtonOff.onclick()
  }

  function createMockButton (defaultClass) {
    let classListData = {}

    let button = {
      classList: {
        add: function (x) {
          classListData[x] = true
        },
        remove: function (x) {
          classListData[x] = false
        },
        contains: function (x) {
          return classListData[x]
        }
      }
    }

    if (defaultClass) classListData[defaultClass] = true

    return button
  }

  function assertStatus (status) {
    if (status === 'off') {
      assert.strictEqual(mockNodeStatusLabel.innerHTML, 'Off')
      assert(mockNodeStatusButtonOff.classList.contains('button-active'), 'Off should be active')
      assert(!mockNodeStatusButtonServing.classList.contains('button-active'), 'Serving should not be active')
      assert(!mockNodeStatusButtonConsuming.classList.contains('button-active'), 'Consuming should not be active')
    } else if (status === 'serving') {
      assert.strictEqual(mockNodeStatusLabel.innerHTML, 'Serving')
      assert(!mockNodeStatusButtonOff.classList.contains('button-active'), 'Off should not be active')
      assert(mockNodeStatusButtonServing.classList.contains('button-active'), 'Serving should be active')
      assert(!mockNodeStatusButtonConsuming.classList.contains('button-active'), 'Consuming should not be active')
    } else if (status === 'consuming') {
      assert.strictEqual(mockNodeStatusLabel.innerHTML, 'Consuming')
      assert(!mockNodeStatusButtonOff.classList.contains('button-active'), 'Off should not be active')
      assert(!mockNodeStatusButtonServing.classList.contains('button-active'), 'Serving should not be active')
      assert(mockNodeStatusButtonConsuming.classList.contains('button-active'), 'Consuming should be active')
    } else if (status === 'invalid') {
      assert.strictEqual(mockNodeStatusLabel.innerHTML, 'There was a problem')
      assert(!mockNodeStatusButtonOff.classList.contains('button-active'), 'Off should not be active')
      assert(!mockNodeStatusButtonServing.classList.contains('button-active'), 'Serving should not be active')
      assert(!mockNodeStatusButtonConsuming.classList.contains('button-active'), 'Consuming should not be active')
    } else {
      assert(false, 'status was not recognized')
    }
  }

  function assertNodeStarted (times = 1) {
    td.verify(mockChildProcess.fork(td.matchers.contains('substratum_node.js'), [], {
      silent: true,
      stdio: [0, 1, 2, 'ipc'],
      detached: true
    }), {times: times})
    td.verify(mockSubstratumNodeProcess.send('start'), {times: times, ignoreExtraArgs: times === 0})
  }

  function assertNodeStopped () {
    td.verify(mockSubstratumNodeProcess.send('stop'))
  }

  function assertNodeNotStopped () {
    td.verify(mockSubstratumNodeProcess.send('stop'), {times: 0, ignoreExtraArgs: true})
  }

  function assertDNSSubverted () {
    td.verify(mockSudoPrompt.exec(td.matchers.contains(/[/\\]static[/\\]binaries[/\\]dns_utility" subvert/), { name: 'DNS utility' }, td.matchers.anything()))
  }

  function assertDNSNotSubverted () {
    td.verify(mockSudoPrompt.exec(td.matchers.contains(/[/\\]static[/\\]binaries[/\\]dns_utility" subvert/)), {times: 0, ignoreExtraArgs: true})
  }

  function assertDNSReverted () {
    td.verify(mockSudoPrompt.exec(td.matchers.contains(/[/\\]static[/\\]binaries[/\\]dns_utility" revert/), { name: 'DNS utility' }, td.matchers.anything()))
  }

  function assertDNSNotReverted () {
    td.verify(mockSudoPrompt.exec(td.matchers.contains(/[/\\]static[/\\]binaries[/\\]dns_utility" revert/)), {times: 0, ignoreExtraArgs: true})
  }
})
