// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global jasmine describe beforeEach afterEach it */

const assert = require('assert')
const path = require('path')
const electronPath = require('electron') // Require Electron from the binaries included in node_modules.
const { Application } = require('spectron')
const WebSocket = require('isomorphic-ws')
const uiInterface = require('../src/render-process/ui_interface')
const consoleWrapper = require('../src/wrappers/console_wrapper')

global.WebSocket = WebSocket

describe('Application launch', function () {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = 20000

  beforeEach(async () => {
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

  afterEach(() => {
    if (this.app && this.app.isRunning()) {
      return this.app.stop()
    }
  })

  it('shows initial state', () => {
    let client = this.app.client
    return client.waitUntilWindowLoaded()
      .then(() => {
        return client.element('div.node-status__actions')
      })
      .then(function (slider) {
        assert.notStrictEqual(slider.type, 'NoSuchElement')
      })
      .then(() => {
        return client.getText('div.node-status__actions button.button-active')
      })
      .then(function (activeButtonText) {
        assert.ok(activeButtonText)
      })
      .then(() => {
        return client.element('.settings-menu--inactive')
      })
      .then(function (settingButton) {
        assert.notStrictEqual(settingButton.type, 'NoSuchElement')
      })
  })

  it('toggles substratum node from off to serving back to off', async () => {
    let client = this.app.client
    await client.waitUntilWindowLoaded()

    await client.element('div.node-status__actions button#serving').click()

    assert.strictEqual((await client.getText('#node-status-label')).toLocaleLowerCase(), 'serving')

    await new Promise(resolve => setTimeout(resolve, 1000))

    let actual = await uiInterface.verifyNodeUp(10000)

    client.getMainProcessLogs().then(function (logs) {
      logs.forEach(function (log) {
        consoleWrapper.log(log)
      })
    })

    if (!actual) {
      // TODO: Fix this for ci under jenkins. See SC-709.
      consoleWrapper.log('SC-709 is still not done to fix this jenkins CI issue.')
    } else {
      assert.strictEqual(actual, true)
    }

    await client.element('div.node-status__actions button#off').click()

    await new Promise(resolve => setTimeout(resolve, 1000))

    assert.strictEqual(await uiInterface.verifyNodeDown(5000), true)
  })
})
