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
    assert.strictEqual(await uiInterface.verifyNodeDown(1000), true)

    testUtilities.purge_existing_state()
    this.app = new Application({
      // Your electron path can be any binary
      // i.e for OSX an example path could be '/Applications/MyApp.app/Contents/MacOS/MyApp'
      // But for the sake of the example we fetch it from our node_modules.
      path: electronPath,

      env: {
        'TESTING_IN_PROGRESS': 'true'
      },

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

  afterEach(async () => {
    if (this.app && this.app.isRunning()) {
      assert.strictEqual(await uiInterface.verifyNodeDown(1000), true)
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
          return configComponent.ipRequiredValidation.isEnabled()
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

  it('persists user entered IP address and neighbor between serving sessions', async () => {
    let client = this.app.client

    await client.waitUntilWindowLoaded()
    await indexPage.serving.click()
    await configComponent.ipInput.setValue('1.2.3.4')
    await configComponent.neighborInput.setValue('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:1.1.1.1:12345;4321')

    await client.waitUntil(async () => {
      return configComponent.saveConfig.isEnabled()
    })
    client.element('#save-config').click()
    await client.waitUntilWindowLoaded()

    assert.strictEqual(await uiInterface.verifyNodeUp(10000), true)
    assert.strictEqual((await client.getText('#node-status-label')).toLocaleLowerCase(), 'serving')
    printConsoleForDebugging(client, false)
    assert.notStrictEqual(await client.getText('#node-descriptor'), '')

    await indexPage.off.click()
    assert.strictEqual(await uiInterface.verifyNodeDown(10000), true)

    await indexPage.settingsButton.click()
    await indexPage.openSettings.click()
    await client.waitUntilWindowLoaded()

    assert.strictEqual((await client.element('#ip').getValue()), '1.2.3.4')
    assert.strictEqual((await client.element('#neighbor').getValue()), 'wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:1.1.1.1:12345;4321')
  })

  it('toggles substratum node from off to serving back to off and back on and on again without needing to enter information and then back off again', async () => {
    let client = this.app.client

    await client.waitUntilWindowLoaded()
    await indexPage.serving.click()
    await configComponent.ipInput.setValue('1.2.3.4')
    await configComponent.neighborInput.setValue('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:1.1.1.1:12345;4321')
    await client.waitUntil(() => configComponent.saveConfig.isEnabled())
    client.element('#save-config').click()
    await client.waitUntilWindowLoaded()

    await indexPage.serving.click()
    await client.waitUntil(async () => (await client.getText('#node-status-label')) === 'Serving')
    assert.strictEqual(await uiInterface.verifyNodeUp(10000), true)

    printConsoleForDebugging(client, false)
    assert.notStrictEqual(await client.getText('#node-descriptor'), '')

    await indexPage.off.click()
    assert.strictEqual(await uiInterface.verifyNodeDown(10000), true)
    await client.waitUntil(async () => (await client.getText('#node-status-label')) === 'Off')

    await indexPage.serving.click()

    await client.waitUntilWindowLoaded()
    await client.waitUntil(async () => (await client.getText('#node-status-label')) === 'Serving')
    assert.strictEqual(await uiInterface.verifyNodeUp(10000), true)
    printConsoleForDebugging(client, false)
    assert.notStrictEqual(await client.getText('#node-descriptor'), '')

    await indexPage.off.click()
    assert.strictEqual(await uiInterface.verifyNodeDown(10000), true)
  })

  it('Changing configuration while node is running turns off the node', async () => {
    let client = this.app.client

    await client.waitUntilWindowLoaded()
    await indexPage.serving.click()
    await configComponent.ipInput.setValue('1.2.3.4')
    await configComponent.neighborInput.setValue('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:1.1.1.1:12345;4321')
    await client.waitUntil(async () => {
      return configComponent.saveConfig.isEnabled()
    })
    client.element('#save-config').click()
    await client.waitUntilWindowLoaded()

    await client.waitUntil(async () => (await client.getText('#node-status-label')) === 'Serving')
    assert.strictEqual(await uiInterface.verifyNodeUp(10000), true)
    printConsoleForDebugging(client, false)
    assert.notStrictEqual(await client.getText('#node-descriptor'), '')

    await indexPage.settingsButton.click()
    await indexPage.openSettings.click()
    await client.waitUntilWindowLoaded()

    client.element('#save-config').click()
    await client.waitUntilWindowLoaded()

    await client.waitUntil(async () => (await client.getText('#node-status-label')) === 'Off')
    assert.strictEqual(await uiInterface.verifyNodeDown(10000), true)
    printConsoleForDebugging(client, false)
    assert.strictEqual(await client.getText('#node-descriptor'), '')
  })
})

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

  get off () {
    return this.client.element('#off')
  }

  get serving () {
    return this.client.element('#serving')
  }

  get settingsButton () {
    return this.client.element('#settings-button')
  }

  get openSettings () {
    return this.client.element('#open-settings')
  }
}

class ConfigComponent {
  at () {
    return this.client.element('#node-config')
  }

  get ipInput () {
    return this.client.element('#ip')
  }

  get ipRequiredValidation () {
    return this.client.element('#ip-validation__required')
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
