// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const td = require('testdouble')
const assert = require('assert')
const {EventEmitter} = require('events')
const util = require('./test_utilities')

describe('NodeActuator', function () {
  let mockChildProcess
  let mockSudoPrompt
  let mockConsole
  let mockPsWrapper

  let mockNodeStatusButtonOff
  let mockNodeStatusButtonServing
  let mockNodeStatusButtonConsuming

  let mockSubstratumNodeProcess

  let mockStatusHandler
  let mockDnsUtility

  let subject

  beforeEach(function () {
    mockChildProcess = td.replace('child_process')
    mockSudoPrompt = td.replace('sudo-prompt')
    mockConsole = td.replace('../wrappers/console_wrapper')
    mockStatusHandler = td.replace('../handlers/status_handler')
    mockDnsUtility = td.replace('../command-process/dns_utility')
    mockPsWrapper = td.replace('../wrappers/ps_wrapper')

    mockNodeStatusButtonOff = util.createMockUIElement('button-active')
    mockNodeStatusButtonServing = util.createMockUIElement()
    mockNodeStatusButtonConsuming = util.createMockUIElement()

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
    subject.bind(mockNodeStatusButtonOff, mockNodeStatusButtonServing, mockNodeStatusButtonConsuming)
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
      assertNodeNotStopped()
    })

    describe('to off', function () {
      beforeEach(function () {
        mockNodeStatusButtonOff.onclick()
      })

      it('does nothing', function () {
        assertStatus('off')
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
        verifyDNSSubverted()
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
        verifyDNSSubverted()
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
      verifyDNSSubverted()
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
        verifyDNSReverted()
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
        verifyDNSReverted()
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

        describe('serve', function () {
          beforeEach(function () {
            mockNodeStatusButtonServing.onclick()
          })

          it('starts the node again', function () {
            assertNodeStarted(2)
          })
        })
      })

      describe('while consuming', function () {
        describe('dns revert succeeds', function () {
          beforeEach(function () {
            mockNodeStatusButtonConsuming.onclick()

            mockSubstratumNodeProcess.emit('message', 'Command returned error: blooga')
          })

          it('reverts the dns', function () {
            verifyDNSReverted(2)
          })

          it('logs the error', function () {
            td.verify(mockConsole.log('substratum_node process received message: ', 'Command returned error: blooga'))
          })

          it('updates the status', function () {
            assertStatus('off')
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
            verifyDNSReverted(2)
          })

          it('logs the error', function () {
            td.verify(mockConsole.log('substratum_node process received error: ', 'blooga'))
          })

          it('updates the status', function () {
            assertStatus('off')
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
            verifyDNSReverted(2)
          })

          it('updates the status', function () {
            assertStatus('off')
          })
        })
      })
    })
  })

  describe('shutdown', function () {
    beforeEach(function () {
      mockNodeStatusButtonServing.onclick()

      subject.shutdown()
    })

    it('reverts the dns', function () {
      verifyDNSReverted(2)
    })

    it('stops the node', function () {
      assertNodeStopped()
    })
  })

  describe('shutdown existing node process', function () {
    beforeEach(function () {
      mockSubstratumNodeProcess = null

      subject.shutdown()
    })

    it('kills the process', function () {
      td.verify(mockPsWrapper.killByName('SubstratumNode'))
    })
  })

  function assertStatus (status) {
    if (status === 'off') {
      td.verify(mockStatusHandler.emit('off'))
    } else if (status === 'serving') {
      td.verify(mockStatusHandler.emit('serving'))
    } else if (status === 'consuming') {
      td.verify(mockStatusHandler.emit('consuming'))
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

  function verifyDNSSubverted () {
    td.verify(mockDnsUtility.subvert())
  }

  function assertDNSNotSubverted () {
    td.verify(mockSudoPrompt.exec(td.matchers.contains(/[/\\]static[/\\]binaries[/\\]dns_utility" subvert/)), {times: 0, ignoreExtraArgs: true})
  }

  function verifyDNSReverted (times = 1) {
    td.verify(mockDnsUtility.revert(), {times: times})
  }

  function assertDNSNotReverted () {
    td.verify(mockSudoPrompt.exec(td.matchers.contains(/[/\\]static[/\\]binaries[/\\]dns_utility" revert/)), {times: 0, ignoreExtraArgs: true})
  }
})
