// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global jasmine describe beforeEach afterEach it */

const assert = require('assert')
const path = require('path')
const electronPath = require('electron') // Require Electron from the binaries included in node_modules.
const { Application } = require('spectron')
const WebSocket = require('isomorphic-ws')
const uiInterface = require('../main-process/ui_interface')
const consoleWrapper = require('../main-process/wrappers/console_wrapper')
const testUtilities = require('./test_utilities')

global.WebSocket = WebSocket

describe('Application launch', function () {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = 20000
  let configComponent
  let indexPage

  beforeEach(async () => {
    testUtilities.purge_existing_state()
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
      .then(() => {
        configComponent = new ConfigComponent(this.app.client)
        indexPage = new IndexPage(this.app.client)
      })
  })

  afterEach(() => {
    if (this.app && this.app.isRunning()) {
      return this.app.stop()
    }
  })

  it('shows the main page with the node in off', () => {
    let client = this.app.client
    return client.waitUntilWindowLoaded()
      .then(() => {
        let nodeConfigComponent = client.element('div.node-config')
        assert.notStrictEqual(nodeConfigComponent.type, 'NoSuchElement')
        let activeButtonText = client.getText('div.node-config button.button-active')
        assert.ok(activeButtonText)
        let saveButton = client.element('#save-config')
        assert.notStrictEqual(saveButton.type, 'NoSuchElement')
      })
      .then(() => {
        let slider = client.element('div.node-status__actions')
        assert.notStrictEqual(slider.type, 'NoSuchElement')
        let activeButtonText = client.getText('div.node-status__actions button.button-active')
        assert.ok(activeButtonText)
        let settingButton = client.element('.settings-menu--inactive')
        assert.notStrictEqual(settingButton.type, 'NoSuchElement')
      })
  })

  it('shows validation messages', () => {
    let client = this.app.client
    return client.waitUntilWindowLoaded()
      .then(async () => {
        await indexPage.serving.click()
        configComponent.ipInput.setValue('jalopy')
        await client.waitUntilTextExists('#ip-validation__pattern', 'Incorrect Format. Should be IPv4 (i.e. 86.75.30.9).')
        assert.ok(!await configComponent.saveConfig.isEnabled())
        await configComponent.ipInput.setValue('')
        await client.keys(['a', 'Backspace'])
        await client.waitUntil(async () => {
          return configComponent.saveConfig.isEnabled()
        })
      })
  })

  it('toggling substratum node to serving prompts for configurations', () => {
    let client = this.app.client
    return client.waitUntilWindowLoaded()
      .then(async () => {
        indexPage.serving.click()
      })
      .then(async () => {
        assert.ok(configComponent.at())
      })
  })

  it('toggles substratum node from off to serving back to off and back on and on again without needing to enter information and then back off again', async () => {
    let client = this.app.client

    await client.waitUntilWindowLoaded()
    await indexPage.serving.click()
    await configComponent.ipInput.setValue('1.2.3.4')
    await configComponent.neighborInput.setValue('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:255.255.255.255:12345;4321')
    await configComponent.walletAddress.setValue('0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    await client.waitUntil(async () => {
      return configComponent.saveConfig.isEnabled()
    })
    client.element('#save-config').click()
    await client.waitUntilWindowLoaded()

    await indexPage.serving.click()
    assert.strictEqual((await client.getText('#node-status-label')).toLocaleLowerCase(), 'serving')
    await wait(1000)
    let nodeUp = await uiInterface.verifyNodeUp(10000)
    printConsoleForDebugging(client, false)
    assert.strictEqual(nodeUp, true)
    assert.notStrictEqual(await client.getText('#node-descriptor'), '')

    await client.element('div.node-status__actions button#off').click()
    await wait(1000)
    assert.strictEqual(await uiInterface.verifyNodeDown(5000), true)

    client.element('#save-config').click()
    await client.waitUntilWindowLoaded()
    await indexPage.serving.click()
    assert.strictEqual((await client.getText('#node-status-label')).toLocaleLowerCase(), 'serving')
    await wait(1000)
    nodeUp = await uiInterface.verifyNodeUp(10000)
    printConsoleForDebugging(client, false)
    assert.strictEqual(nodeUp, true)
    assert.notStrictEqual(await client.getText('#node-descriptor'), '')

    await client.element('div.node-status__actions button#off').click()
    await wait(1000)
    assert.strictEqual(await uiInterface.verifyNodeDown(5000), true)
  })
})

function wait (ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function printConsoleForDebugging (client, debug) {
  if (!debug) { return }
  client.getMainProcessLogs().then(function (logs) {
    logs.forEach(function (log) {
      consoleWrapper.log(log)
    })
  })
}

class IndexPage {
  constructor (client) {
    this.client = client
  }

  at () {
    return this.client.element('#index-page')
  }

  get serving () {
    return this.client.element('#serving')
  }
}

class ConfigComponent {
  at () {
    return this.client.element('#node-config')
  }

  get ipInput () {
    return this.client.element('#ip')
  }

  get neighborInput () {
    return this.client.element('#neighbor')
  }

  get walletAddress () {
    return this.client.element('#wallet-address')
  }

  get saveConfig () {
    return this.client.element('#save-config')
  }

  constructor (client) {
    this.client = client
  }
}
