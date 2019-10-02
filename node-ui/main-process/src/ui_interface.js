// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

const webSocketWrapper = require('./wrappers/websocket_wrapper.js')

module.exports = (() => {
  const DEFAULT_UI_PORT = 5333
  const UI_INTERFACE_URL = 'ws://127.0.0.1'
  const UI_PROTOCOL = 'SubstratumNode-UI'
  const CONNECT_TIMEOUT = 5000
  let webSocket = null
  let getNodeDescriptorCallbackPair = null
  let setConsumingWalletPasswordCallbackPair = null
  let getFinancialStatisticsCallbackPair = null
  let getNeighborhoodDotGraphCallbackPair = null
  let setGasPriceCallbackPair = null

  function connect () {
    return new Promise((resolve, reject) => {
      const ws = createSocket(DEFAULT_UI_PORT)
      ws.onopen = () => {
        webSocket = ws
        resolve(true)
      }
      ws.onmessage = (evt) => {
        const data = JSON.parse(evt.data)

        const nodeDescriptor = data.NodeDescriptor
        if (nodeDescriptor) {
          getNodeDescriptorCallbackPair.resolve(nodeDescriptor)
        }

        const success = data.SetWalletPasswordResponse
        if (success !== undefined) {
          setConsumingWalletPasswordCallbackPair.resolve(success)
        }

        const successGas = data.SetGasPriceResponse
        if (successGas !== undefined) {
          setGasPriceCallbackPair.resolve(successGas)
        }

        const financialStatistics = data.FinancialStatisticsResponse
        if (financialStatistics) {
          getFinancialStatisticsCallbackPair.resolve(financialStatistics)
        }

        const neighborhoodDotGraph = data.NeighborhoodDotGraphResponse
        if (neighborhoodDotGraph) {
          getNeighborhoodDotGraphCallbackPair.resolve(neighborhoodDotGraph)
        }
      }
      ws.onerror = (event) => {
        if (getNodeDescriptorCallbackPair) {
          getNodeDescriptorCallbackPair.reject()
        }

        if (setConsumingWalletPasswordCallbackPair) {
          setConsumingWalletPasswordCallbackPair.reject()
        }

        if (setGasPriceCallbackPair) {
          setGasPriceCallbackPair.reject()
        }

        if (getFinancialStatisticsCallbackPair) {
          getFinancialStatisticsCallbackPair.reject()
        }

        if (getNeighborhoodDotGraphCallbackPair) {
          getNeighborhoodDotGraphCallbackPair.reject()
        }

        webSocket = null
        reject(event)
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

  /**
   * tries to connect to the websocket. if it fails other than by timeout it returns true
   * @param timeoutMillis
   * @returns {Promise<boolean>}
   */
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
    webSocket.send('"ShutdownMessage"')
    webSocket.close()
    webSocket = null
  }

  async function getNodeDescriptor () {
    if (getNodeDescriptorCallbackPair) {
      return Promise.reject(Error('CallAlreadyInProgress'))
    }
    return new Promise((resolve, reject) => {
      getNodeDescriptorCallbackPair = {
        resolve: (descriptor) => {
          getNodeDescriptorCallbackPair = null
          resolve(descriptor)
        },
        reject: (e) => {
          reject(e)
        }
      }
      webSocket.send('"GetNodeDescriptor"')
    })
  }

  async function setConsumingWalletPassword (password) {
    if (setConsumingWalletPasswordCallbackPair) {
      return Promise.reject(Error('CallAlreadyInProgress'))
    }
    return new Promise((resolve, reject) => {
      setConsumingWalletPasswordCallbackPair = {
        resolve: (success) => {
          setConsumingWalletPasswordCallbackPair = null
          resolve(success)
        },
        reject: (e) => {
          reject(e)
        }
      }
      webSocket.send(`{"SetWalletPassword": "${password}"}`)
    })
  }

  async function setGasPrice (gasPrice) {
    if (!webSocket) return Promise.reject(Error('WebsocketNotConnected'))

    if (setGasPriceCallbackPair) {
      return Promise.reject(Error('CallAlreadyInProgress'))
    }
    return new Promise((resolve, reject) => {
      setGasPriceCallbackPair = {
        resolve: (success) => {
          setGasPriceCallbackPair = null
          resolve(success)
        },
        reject: (e) => {
          reject(e)
        }
      }
      webSocket.send(`{"SetGasPrice": "${gasPrice}"}`)
    })
  }

  async function getFinancialStatistics () {
    if (getFinancialStatisticsCallbackPair) {
      return Promise.reject(Error('CallAlreadyInProgress'))
    }
    return new Promise((resolve, reject) => {
      getFinancialStatisticsCallbackPair = {
        resolve: (success) => {
          getFinancialStatisticsCallbackPair = null
          resolve(success)
        },
        reject: (e) => {
          reject(e)
        }
      }
      webSocket.send('"GetFinancialStatisticsMessage"')
    })
  }

  async function getNeighborhoodDotGraph () {
    if (getNeighborhoodDotGraphCallbackPair) {
      return Promise.reject(Error('CallAlreadyInProgress'))
    }
    return new Promise((resolve, reject) => {
      getNeighborhoodDotGraphCallbackPair = {
        resolve: (success) => {
          getNeighborhoodDotGraphCallbackPair = null
          resolve(success)
        },
        reject: (e) => {
          reject(e)
        }
      }
      webSocket.send('"NeighborhoodDotGraphRequest"')
    })
  }

  function createSocket (port) {
    return webSocketWrapper.create(`${UI_INTERFACE_URL}:${port}`, UI_PROTOCOL, { handshakeTimeout: CONNECT_TIMEOUT })
  }

  return {
    DEFAULT_UI_PORT: DEFAULT_UI_PORT,
    UI_INTERFACE_URL: UI_INTERFACE_URL,
    UI_PROTOCOL: UI_PROTOCOL,
    CONNECT_TIMEOUT: CONNECT_TIMEOUT,
    connect: connect,
    isConnected: isConnected,
    verifyNodeUp: verifyNodeUp,
    verifyNodeDown: verifyNodeDown,
    shutdown: shutdown,
    getNodeDescriptor: getNodeDescriptor,
    setConsumingWalletPassword: setConsumingWalletPassword,
    setGasPrice: setGasPrice,
    getFinancialStatistics: getFinancialStatistics,
    getNeighborhoodDotGraph: getNeighborhoodDotGraph
  }
})()
