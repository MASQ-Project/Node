// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const path = require('path')
const electronPath = require('electron') // Require Electron from the binaries included in node_modules.
const {Application} = require('spectron')

describe('Application launch', function () {
  this.timeout(10000)

  beforeEach(function () {
    this.app = new Application({
      // Your electron path can be any binary
      // i.e for OSX an example path could be '/Applications/MyApp.app/Contents/MacOS/MyApp'
      // But for the sake of the example we fetch it from our node_modules.
      path: electronPath,

      // Assuming you have the following directory structure

      //  |__ my project
      //   |__ ...
      //   |__ main.js
      //   |__ package.json
      //   |__ index.html
      //   |__ ...
      //   |__ test
      //    |__ spec.js  <- You are here! ~ Well you should be.

      // The following line tells spectron to look and use the main.js file
      // and the package.json located 1 level above.
      args: [path.join(__dirname, '..')]
    })
    return this.app.start()
  })

  afterEach(function () {
    if (this.app && this.app.isRunning()) {
      return this.app.stop()
    }
  })

  it('shows initial state', function () {
    let client = this.app.client
    return client.waitUntilWindowLoaded()
      .then(function () {
        return client.getAttribute('#toggle_node_off', 'checked')
      }).then(function (result) {
        assert.strictEqual(result, 'true')
        return client.getAttribute('#toggle_node_on', 'checked')
      }).then(function (result) {
        assert.strictEqual(result, null)
      })
  })

  it('toggles substratum node on and off', function () {
    let client = this.app.client
    return client.waitUntilWindowLoaded()
      .then(function () {
        var toggleOn = client.element('#control-panel').element('#toggle_node_on')
        return toggleOn.click()
      }).then(function () {
        return client.getAttribute('#toggle_node_on', 'checked')
      }).then(function (result) {
        assert.strictEqual(result, 'true')
        var toggleOff = client.element('#control-panel').element('#toggle_node_off')
        return toggleOff.click()
      }).then(function () {
        return client.getAttribute('#toggle_node_off', 'checked')
      }).then(function (result) {
        assert.strictEqual(result, 'true')
        return client.getRenderProcessLogs()
      }).then(function (logs) {
        if (process.platform !== 'win32') {
          var logMessageExists = false
          logs.forEach(function (log) {
            if (log.message.includes('substratum_node process exited with code ')) {
              logMessageExists = true
            }
          })
          assert.ok(logMessageExists)
        }
      })
  })
})
