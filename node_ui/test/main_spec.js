// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const path = require('path')
const electronPath = require('electron') // Require Electron from the binaries included in node_modules.
const {Application} = require('spectron')

describe('Application launch', function () {
  this.timeout(10000)

  beforeEach(() => {
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

  it('toggles substratum node from off to serving back to off', () => {
    let client = this.app.client
    let wait = ms => new Promise(resolve => setTimeout(resolve, ms))
    return client.waitUntilWindowLoaded()
      .then(() => {
        let sliderMask = client.element('div.node-status__actions button#serving')
        sliderMask.click()
      })
      .then(() => {
        return client.getText('#node-status-label')
      })
      .then(function (result) {
        assert.strictEqual(result.toLocaleLowerCase(), 'serving')
      })
      .then(() => {
        let sliderMask = client.element('div.node-status__actions button#off')
        sliderMask.click()
      })
      .then(() => {
        return wait(500)
      })
      .then(() => {
        return client.getText('#node-status-label')
      })
      .then(function (result) {
        assert.strictEqual(result.toLocaleLowerCase(), 'off')
      })
      .then(() => {
        return client.getRenderProcessLogs()
      })
      .then(function (logs) {
        let matchingLogs = logs.filter(function (log) {
          return log.message.includes('substratum_node process exited with code ')
        })
        let logsMsg = logs.map(function (log) {
          return log.message
        })
        assert.ok(matchingLogs.length > 0, 'Did not find exit log in:\n' + logsMsg.join('\n'))
      })
  })
})
