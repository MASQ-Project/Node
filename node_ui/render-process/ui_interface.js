// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

const webSocketWrapper = require('../wrappers/websocket_wrapper.js')

module.exports = (() => {
  const DEFAULT_UI_PORT = 5333
  const UI_INTERFACE_URL = `ws://127.0.0.1`
  const UI_PROTOCOL = 'SubstratumNode-UI'
  let webSocket

  function connect () {
    return new Promise((resolve, reject) => {
      let ws = createSocket(DEFAULT_UI_PORT)
      ws.onopen = () => {
        // TODO Remember set onmessage and reset onerror when we go bidirectional
        webSocket = ws
        resolve(true)
      }
      ws.onerror = (err) => {
        reject(err)
      }
    })
  }

  function isConnected () {
    return !!webSocket
  }

  async function verifyNodeUp (timeoutMillis) {
    return new Promise((resolve) => {
      if (timeoutMillis <= 0) {
        resolve(false)
      } else {
        const finishBy = Date.now() + timeoutMillis
        const onerror = () => {
          setTimeout(async () => {
            const nextTimeout = finishBy - Date.now()
            resolve(await verifyNodeUp(nextTimeout))
          }, 250)
        }

        try {
          const socket = createSocket(DEFAULT_UI_PORT)
          socket.onopen = () => {
            socket.close()
            resolve(true)
          }
          socket.onerror = onerror
        } catch (error) {
          onerror()
        }
      }
    })
  }

  async function verifyNodeDown (timeoutMillis) {
    return new Promise((resolve) => {
      if (timeoutMillis <= 0) {
        resolve(false)
      } else {
        const finishBy = Date.now() + timeoutMillis
        const onerror = () => {
          resolve(true)
        }
        try {
          const socket = createSocket(DEFAULT_UI_PORT)
          socket.onopen = () => {
            socket.close()
            setTimeout(async () => {
              const nextTimeout = finishBy - Date.now()
              resolve(await verifyNodeDown(nextTimeout))
            }, 250)
          }
          socket.onerror = onerror
        } catch (error) {
          onerror()
        }
      }
    })
  }

  function shutdown () {
    webSocket.send(JSON.stringify({message_type: 'shutdown'}))
    webSocket.close()
    webSocket = null
  }

  function createSocket (port) {
    return webSocketWrapper.create(`${UI_INTERFACE_URL}:${port}`, UI_PROTOCOL)
  }

  return {
    DEFAULT_UI_PORT: DEFAULT_UI_PORT,
    UI_INTERFACE_URL: UI_INTERFACE_URL,
    UI_PROTOCOL: UI_PROTOCOL,
    connect: connect,
    isConnected: isConnected,
    verifyNodeUp: verifyNodeUp,
    verifyNodeDown: verifyNodeDown,
    shutdown: shutdown
  }
})()
