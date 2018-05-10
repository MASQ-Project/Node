// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (function () {
  const childProcess = require('child_process')
  const {EventEmitter} = require('events')
  const path = require('path')
  const util = require('util')
  const console = require('../wrappers/console_wrapper')

  var substratumNodeProcess

  function NodeToggler () {
    var self = this
    EventEmitter.call(self)

    this.bindEventsToProcess = function () {
      substratumNodeProcess.on('message', function (message) {
        console.log('substratum_node process received message: ', message)
        if (message.startsWith('Command returned error: ')) {
          self.emit('toggle_error')
        }
      })

      substratumNodeProcess.on('error', function (error) {
        console.log('substratum_node process received error: ', error.message)
        self.emit('toggle_error')
      })

      substratumNodeProcess.on('exit', function (code) {
        console.log('substratum_node process exited with code ', code)
      })
    }

    this.startProcess = function () {
      const worker = path.resolve(__dirname, '.', '../command-process/substratum_node.js')
      substratumNodeProcess = childProcess.fork(worker, [], {
        silent: true,
        stdio: [0, 1, 2, 'ipc'],
        detached: true
      })
      this.bindEventsToProcess()
      substratumNodeProcess.send('start')
    }

    this.stopProcess = function () {
      substratumNodeProcess.send('stop')
    }
  }
  util.inherits(NodeToggler, EventEmitter)

  return {
    NodeToggler: NodeToggler
  }
}())
