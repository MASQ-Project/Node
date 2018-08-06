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
        return client.element('div.node-status__actions')
      })
      .then(function (slider) {
        assert.notStrictEqual(slider.type, 'NoSuchElement')
      })
      .then(function () {
        return client.getText('div.node-status__actions button.button-active')
      })
      .then(function (activeButtonText) {
        assert.ok(activeButtonText)
      })
      .then(function () {
        return client.element('.settings-menu--inactive')
      })
      .then(function (settingButton) {
        assert.notStrictEqual(settingButton.type, 'NoSuchElement')
      })
  })

  // This test never really worked because we can't interact with the sudo prompt
  // It seems like it just completes before it has a chance to prompt
  // TODO: How can we test something meaningful here?
  it('toggles substratum node from off to serving back to off', function () {
    let client = this.app.client
    return client.waitUntilWindowLoaded()
      .then(function () {
        let sliderMask = client.element('div.node-status__actions button#serving')
        sliderMask.click()
      })
      .then(function () {
        return client.getText('#node-status-label')
      })
      .then(function (result) {
        assert.strictEqual(result.toLocaleLowerCase(), 'serving')
      })
      .then(function () {
        let sliderMask = client.element('div.node-status__actions button#off')
        sliderMask.click()
      })
      .then(function () {
        return client.getText('#node-status-label')
      })
      .then(function (result) {
        assert.strictEqual(result.toLocaleLowerCase(), 'off')
      })
      // .then(function () {
      //   return client.getRenderProcessLogs()
      // })
      // .then(function (logs) {
      //   // FIXME Failing on Jenkins
      //    if (process.platform !== 'win32') {
      //      let logMessageExists = false
      //      logs.forEach(function (log) {
      //        if (log.message.includes('substratum_node process exited with code ')) {
      //          logMessageExists = true
      //        }
      //      })
      //      assert.ok(logMessageExists)
      //    }
      // })
  })
})
