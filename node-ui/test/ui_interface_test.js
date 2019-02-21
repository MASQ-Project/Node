// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const td = require('testdouble')
const assert = require('assert')

describe('Given a mock WebSocket', () => {
  let mockWebSocketWrapper
  let uiInterface
  beforeEach(() => {
    mockWebSocketWrapper = td.replace('../src/wrappers/websocket_wrapper')
    uiInterface = require('../src/main-process/ui_interface')
  })

  afterEach(() => {
    td.reset()
  })

  describe('and a real UiInterface', () => {
    let subject
    beforeEach(() => {
      subject = uiInterface
    })

    it('the subject has the proper default port', () => {
      assert.strictEqual(subject.DEFAULT_UI_PORT, 5333)
    })

    it('the subject has the proper UI interface URL', () => {
      assert.strictEqual(subject.UI_INTERFACE_URL, 'ws://127.0.0.1')
    })

    it('the subject has the proper UI protocol', () => {
      assert.strictEqual(subject.UI_PROTOCOL, 'SubstratumNode-UI')
    })

    describe('that is immediately asked whether it is connected', () => {
      let result
      beforeEach(() => {
        result = subject.isConnected()
      })

      it('it says no', () => {
        assert.strictEqual(result, false)
      })
    })

    describe('and the UiInterface is connected', () => {
      let webSocketClient, connectPromise
      beforeEach(() => {
        webSocketClient = td.object(['send', 'close', 'onopen', 'onmessage', 'onerror'])
        td.when(mockWebSocketWrapper.create(`${subject.UI_INTERFACE_URL}:${subject.DEFAULT_UI_PORT}`,
          subject.UI_PROTOCOL)).thenReturn(webSocketClient)

        connectPromise = subject.connect()
      })

      describe('and asked whether it is connected', () => {
        let result
        beforeEach(() => {
          result = subject.isConnected()
        })

        it('it says no, not yet', () => {
          assert.strictEqual(result, false)
        })
      })

      describe('but experiences a connection error', () => {
        let result
        beforeEach(async () => {
          webSocketClient.onerror('My tummy hurts')
          try {
            await connectPromise
          } catch (err) {
            result = err
          }
        })

        it('rejects the promise', () => {
          assert.strictEqual(result, 'My tummy hurts')
        })

        it('says it\'s not connected', () => {
          assert.strictEqual(subject.isConnected(), false)
        })
      })

      describe('and the connection succeeds', () => {
        let result
        beforeEach(async () => {
          webSocketClient.onopen()
          result = await connectPromise
        })

        it('resolves the promise with true', () => {
          assert.strictEqual(result, true)
        })

        it('says it\'s now connected', () => {
          assert.strictEqual(subject.isConnected(), true)
        })

        describe('when it is directed to send a shutdown message', () => {
          beforeEach(() => {
            subject.shutdown()
          })

          it('the WebSocket client is instructed to send the proper message', () => {
            let captor = td.matchers.captor()
            td.verify(webSocketClient.send(captor.capture()))
            assert.deepStrictEqual(JSON.parse(captor.value), {message_type: 'shutdown'})
          })

          it('the WebSocket client is closed', () => {
            td.verify(webSocketClient.close())
          })

          it('the UiInterface claims to be no longer connected', () => {
            assert.strictEqual(subject.isConnected(), false)
          })
        })
      })
    })
  })

  describe('and a mock client to configure', () => {
    let webSocketClients, webSocketClientIndex, doConnectSuccess, result, start, end
    beforeEach(() => {
      webSocketClients = [...new Array(10).keys()].map((n) => td.object(['close', 'onopen', 'onerror']))
      doConnectSuccess = () => {
        const webSocketClient = webSocketClients[webSocketClientIndex]
        webSocketClientIndex += 1
        return webSocketClient
      }
      webSocketClientIndex = 0
      td.when(mockWebSocketWrapper.create(td.matchers.anything(), td.matchers.anything())).thenDo(doConnectSuccess)
    })

    describe('when verifyNodeUp succeeds immediately', () => {
      beforeEach(async () => {
        const subject = uiInterface
        start = Date.now()

        const promise = subject.verifyNodeUp(2000)
        setTimeout(() => {
          webSocketClients[0].onopen()
        }, 0)
        result = await promise

        end = Date.now()
      })

      it('calls the constructor exactly once', () => {
        assert.strictEqual(webSocketClientIndex, 1)
      })

      it('closes it, returns quickly, and reports that the Node is up', () => {
        td.verify(webSocketClients[0].close())
      })

      it('returns quickly', () => {
        assert(end - start < 250)
      })

      it('reports that the Node is up', () => {
        assert.strictEqual(result, true)
      })
    })

    describe('when verifyNodeUp succeeds after two non-exceptional failures', () => {
      beforeEach(async () => {
        const subject = uiInterface
        start = Date.now()

        const promise = subject.verifyNodeUp(2000)
        setTimeout(() => {
          webSocketClients[0].onerror()
          setTimeout(() => {
            webSocketClients[1].onerror()
            setTimeout(() => {
              webSocketClients[2].onopen()
            }, 300)
          }, 300)
        }, 0)
        result = await promise

        end = Date.now()
      })

      it('calls the constructor three times', () => {
        assert.strictEqual(webSocketClientIndex, 3)
      })

      it('closes the successfully-opened socket', () => {
        td.verify(webSocketClients[2].close())
      })

      it('returns after an appropriate delay', () => {
        assert(end - start >= 500)
        assert(end - start < 1000)
      })

      it('reports that the Node is up', () => {
        assert.strictEqual(result, true)
      })
    })

    describe('when verifyNodeUp fails until timeout', () => {
      beforeEach(async () => {
        const subject = uiInterface
        start = Date.now()

        const promise = subject.verifyNodeUp(450)
        setTimeout(() => {
          webSocketClients[0].onerror()
          setTimeout(() => {
            webSocketClients[1].onerror()
          }, 300)
        }, 0)
        result = await promise

        end = Date.now()
      })

      it('calls the constructor twice', () => {
        assert.strictEqual(webSocketClientIndex, 2)
      })

      it('returns after at least 450ms but not too long', () => {
        assert(end - start >= 500)
        assert(end - start < 1000)
      })

      it('reports that the Node is not yet up', () => {
        assert.strictEqual(result, false)
      })
    })

    describe('when verifyNodeDown succeeds immediately', () => {
      beforeEach(async () => {
        const subject = uiInterface
        start = Date.now()

        const promise = subject.verifyNodeDown(2000)
        setTimeout(() => {
          webSocketClients[0].onerror()
        }, 0)
        result = await promise

        end = Date.now()
      })

      it('calls the constructor exactly once', () => {
        assert.strictEqual(webSocketClientIndex, 1)
      })

      it('returns quickly', () => {
        assert(end - start < 250)
      })

      it('reports that the Node is down', () => {
        assert.strictEqual(result, true)
      })
    })

    describe('when verifyNodeDown fails to connect after two successes', () => {
      beforeEach(async () => {
        const subject = uiInterface
        start = Date.now()

        const promise = subject.verifyNodeDown(2000)
        setTimeout(() => {
          webSocketClients[0].onopen()
          setTimeout(() => {
            webSocketClients[1].onopen()
            setTimeout(() => {
              webSocketClients[2].onerror()
            }, 300)
          }, 300)
        }, 0)
        result = await promise

        end = Date.now()
      })

      it('calls the constructor three times', () => {
        assert.strictEqual(webSocketClientIndex, 3)
      })

      it('closes connections', () => {
        td.verify(webSocketClients[0].close())
        td.verify(webSocketClients[1].close())
      })

      it('returns after an appropriate delay', () => {
        assert(end - start >= 500)
        assert(end - start < 1000)
      })

      it('reports that the Node is down', () => {
        assert.strictEqual(result, true)
      })
    })

    describe('when verifyNodeDown succeeds until timeout', () => {
      beforeEach(async () => {
        const subject = uiInterface
        start = Date.now()

        const promise = subject.verifyNodeDown(450)
        setTimeout(() => {
          webSocketClients[0].onopen()
          setTimeout(() => {
            webSocketClients[1].onopen()
          }, 300)
        }, 0)
        result = await promise

        end = Date.now()
      })

      it('calls the constructor twice', () => {
        assert.strictEqual(webSocketClientIndex, 2)
      })

      it('closes connections', () => {
        td.verify(webSocketClients[0].close())
        td.verify(webSocketClients[1].close())
      })

      it('returns after at least 450ms but not too long', () => {
        assert(end - start >= 500)
        assert(end - start < 1000)
      })

      it('reports that the Node is not yet down', () => {
        assert.strictEqual(result, false)
      })
    })
  })

  describe('and a mock client to configure for exceptions', () => {
    let result, start, end
    beforeEach(() => {
      td.when(mockWebSocketWrapper.create(td.matchers.anything(), td.matchers.anything())).thenThrow(new Error(''))
    })

    describe('when verifyNodeUp fails with exceptions until timeout', () => {
      beforeEach(async () => {
        const subject = uiInterface
        start = Date.now()

        result = await subject.verifyNodeUp(450)

        end = Date.now()
      })

      it('returns after at least 450ms but not too long', () => {
        assert(end - start >= 500)
        assert(end - start < 1000)
      })

      it('reports that the Node is not yet up', () => {
        assert.strictEqual(result, false)
      })
    })

    describe('when verifyNodeDown fails with an exception', () => {
      beforeEach(async () => {
        const subject = uiInterface
        start = Date.now()

        result = await subject.verifyNodeDown(2000)

        end = Date.now()
      })

      it('returns quickly', () => {
        assert(end - start < 250)
      })

      it('reports that the Node is already down', () => {
        assert.strictEqual(result, true)
      })
    })
  })
})
