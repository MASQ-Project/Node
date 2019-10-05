// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global jasmine describe beforeEach afterEach it */

const assert = require('assert')
const fs = require('fs')
const path = require('path')
const electronPath = require('electron') // Require Electron from the binaries included in node_modules.
const { Application } = require('spectron')
const WebSocket = require('isomorphic-ws')
const uiInterface = require('../src/ui_interface')
const consoleWrapper = require('../src/wrappers/console_wrapper')
const testUtilities = require('./test_utilities')
const generatedBasePath = 'generated/main_spec'

global.WebSocket = WebSocket

describe('After application launch: ', function () {
  jasmine.DEFAULT_TIMEOUT_INTERVAL = 20000
  let configComponent
  let indexPage
  let currentSpec

  const specReporter = {
    specStarted: function (result) {
      currentSpec = result
    },
    specDone: function (result) {
      currentSpec = null
    }
  }
  jasmine.getEnv().addReporter(specReporter)

  beforeEach(async () => {
    const currentSpecFolderName = currentSpec.description.replace(/ /g, '_').toLowerCase()
    assert.strictEqual(await uiInterface.verifyNodeDown(1000), true, 'node was up at start of test')

    testUtilities.purgeExistingState()
    const chromeDriverArguments = [
      '--headless',
      '--no-sandbox',
      '--ignore-gpu-blacklist' // said to help in restrictive build environments (e.g. Azure)
    ]
    this.app = new Application({
      // Your electron path can be any binary
      // i.e for OSX an example path could be '/Applications/MyApp.app/Contents/MacOS/MyApp'
      // But for the sake of the example we fetch it from our node_modules.
      path: electronPath,

      env: {
        TESTING_IN_PROGRESS: 'true',
        ELECTRON_USER_DATA: `${process.cwd()}/${generatedBasePath}/${currentSpecFolderName}/${process.hrtime.bigint()}/userData`
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
      args: [path.join(__dirname, '..')],
      chromeDriverArgs: chromeDriverArguments
    })

    return this.app.start()
      .then(() => {
        configComponent = new ConfigComponent(this.app.client)
        indexPage = new IndexPage(this.app.client)
      })
  })

  afterEach(async () => {
    // Uncomment the next line to see web driver logs
    // this.app.client.log('driver').then((msg) => { console.log(msg) })
    printConsoleForDebugging(this.app.client, false)
    if (this.app && this.app.isRunning()) {
      const imageFile = this.app.env.ELECTRON_USER_DATA + '/Screenshot.png'
      this.app.browserWindow.capturePage().then((imageBuffer) => {
        try {
          fs.writeFileSync(imageFile, imageBuffer)
        } catch (error) {
          throw new Error(error)
        }
      }).catch((error) => {
        console.log(`Failed to save screenshot to ${imageFile} because ${error.message}`)
      })
      const result = this.app.stop()
      assert.strictEqual(await uiInterface.verifyNodeDown(10000), true,
        'node did not go down after app.stop()')
      return result
    }
  })

  it('shows the main page with the node in off', () => {
    const client = this.app.client
    return client.waitUntilWindowLoaded()
      .then(() => {
        const nodeConfigComponent = client.element('div.node-status')
        assert.notStrictEqual(nodeConfigComponent.type, 'NoSuchElement')
        const activeButtonText = client.getText('div.node-status button.button-active')
        assert.ok(activeButtonText)
        const saveButton = client.element('#save-config')
        assert.notStrictEqual(saveButton.type, 'NoSuchElement')
      })
      .then(() => {
        const slider = client.element('div.node-status__actions')
        assert.notStrictEqual(slider.type, 'NoSuchElement')
        const activeButtonText = client.getText('div.node-status__actions button.button-active')
        assert.ok(activeButtonText)
        const settingButton = client.element('.settings-menu--inactive')
        assert.notStrictEqual(settingButton.type, 'NoSuchElement')
      })
  })

  it('shows validation messages', () => {
    const client = this.app.client
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
    const client = this.app.client
    return client.waitUntilWindowLoaded()
      .then(async () => {
        indexPage.serving.click()
      })
      .then(async () => {
        assert.ok(configComponent.at())
      })
  })

  it('persists user entered IP address and neighbor between serving sessions', async () => {
    const client = this.app.client

    await client.waitUntilWindowLoaded()
    await indexPage.serving.click()
    await configComponent.ipInput.setValue('1.2.3.4')
    await configComponent.neighborInput.setValue('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:1.1.1.1:12345;4321')
    await configComponent.blockchainServiceUrl.setValue('https://127.0.0.1')

    await client.waitUntil(async () => {
      return configComponent.saveConfig.isEnabled()
    })
    client.element('#save-config').click()
    await client.waitUntilWindowLoaded()

    assert.strictEqual(await uiInterface.verifyNodeUp(15000), true, 'node was not up after saving config')
    await client.waitUntil(async () => (await client.getText('#node-status-label') === 'Serving'), 10000,
      'Timed out waiting for Node Status to switch to \'Serving\'')
    assert.strictEqual((await client.getText('#node-status-label')), 'Serving')
    await client.waitUntil(async () => (await client.getText('#node-descriptor') !== ''), 5000, 'Timed out waiting for Node Descriptor')

    await indexPage.off.click()
    assert.strictEqual(await uiInterface.verifyNodeDown(10000), true, 'node did not go down after clicking off')

    await indexPage.settingsButton.click()
    await indexPage.openSettings.click()
    await client.waitUntilWindowLoaded()

    assert.strictEqual((await client.element('#ip').getValue()), '1.2.3.4')
    assert.strictEqual((await client.element('#neighbor').getValue()), 'wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:1.1.1.1:12345;4321')
  })

  it('persists our node descriptor when navigating to another page', async () => {
    const client = this.app.client

    await client.waitUntilWindowLoaded()
    await indexPage.serving.click()
    await configComponent.ipInput.setValue('1.2.3.4')
    await configComponent.neighborInput.setValue('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:1.1.1.1:12345;4321')
    await configComponent.blockchainServiceUrl.setValue('http://127.0.0.1')

    await client.waitUntil(async () => {
      return configComponent.saveConfig.isEnabled()
    })
    client.element('#save-config').click()
    await client.waitUntilWindowLoaded()

    assert.strictEqual(await uiInterface.verifyNodeUp(15000), true, 'node was not up after saving config')

    await client.waitUntil(async () => (await client.getText('#node-status-label') === 'Serving'), 5000,
      'Timed out waiting for Node Status to switch to \'Serving\'')
    await client.waitUntil(async () => (await indexPage.nodeDescriptor.getText() !== ''), 5000, 'Timed out waiting for Node Descriptor')

    await indexPage.settingsButton.click()
    await indexPage.networkSettings.click()
    await client.waitUntilWindowLoaded()

    client.element('#cancel').click()
    await client.waitUntilWindowLoaded()

    await client.waitUntil(async () => (await client.getText('#node-descriptor')) !== '')

    await indexPage.off.click()
    assert.strictEqual(await uiInterface.verifyNodeDown(10000), true, 'node did not go down after clicking off')
  })

  it('toggles substratum node from off to serving back to off and back on and on again without needing to enter information and then back off again', async () => {
    const client = this.app.client

    await client.waitUntilWindowLoaded()
    await indexPage.serving.click()
    await configComponent.ipInput.setValue('1.2.3.4')
    await configComponent.neighborInput.setValue('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:1.1.1.1:12345;4321')
    await configComponent.blockchainServiceUrl.setValue('https://127.0.0.1')
    await client.waitUntil(() => configComponent.saveConfig.isEnabled())
    client.element('#save-config').click()

    assert.strictEqual(await uiInterface.verifyNodeUp(15000), true, 'node was not up after saving config')

    await client.waitUntil(async () => (await client.getText('#node-status-label') === 'Serving'), 5000,
      'Timed out waiting for Node Status to switch to \'Serving\'')
    await client.waitUntil(async () => (await client.getText('#node-descriptor') !== ''), 5000, 'Timed out waiting for Node Descriptor')

    await indexPage.off.click()
    assert.strictEqual(await uiInterface.verifyNodeDown(10000), true, 'node did not go down after clicking off')

    await client.waitUntil(async () => (await client.getText('#node-status-label') === 'Off'), 5000,
      'Timed out waiting for Node Status to switch to \'Off\' after switching to \'Serving\'')

    await indexPage.serving.click()

    assert.strictEqual(await uiInterface.verifyNodeUp(15000), true, 'node was not up after clicking serving')

    await client.waitUntil(async () => (await client.getText('#node-status-label') === 'Serving'), 5000,
      'Timed out waiting for Node Status to switch to \'Serving\' after switching to \'Off\'')
    assert.strictEqual(await uiInterface.verifyNodeUp(15000), true, 'node was not up')
    await client.waitUntil(async () => (await client.getText('#node-descriptor') !== ''), 5000,
      'Timed out waiting for Node Descriptor')

    await indexPage.off.click()
    assert.strictEqual(await uiInterface.verifyNodeDown(10000), true, 'node did not go down after clicking off')
  })

  it('Changing configuration while node is running turns off the node', async () => {
    const client = this.app.client

    await client.waitUntilWindowLoaded()
    await indexPage.serving.click()
    await configComponent.ipInput.setValue('1.2.3.4')
    await configComponent.neighborInput.setValue('wsijSuWax0tMAiwYPr5dgV4iuKDVIm5/l+E9BYJjbSI:1.1.1.1:12345;4321')
    await configComponent.blockchainServiceUrl.setValue('https://127.0.0.1')

    await client.waitUntil(async () => {
      return configComponent.saveConfig.isEnabled()
    })
    client.element('#save-config').click()
    await client.waitUntilWindowLoaded()

    assert.strictEqual(await uiInterface.verifyNodeUp(15000), true, 'node was not up after saving config')

    await client.waitUntil(async () => (await client.getText('#node-status-label') === 'Serving'), 5000,
      'Timed out waiting for Node Status to switch to \'Serving\'')
    await client.waitUntil(async () => (await indexPage.nodeDescriptor.getText()) !== '')

    await indexPage.settingsButton.click()
    await indexPage.openSettings.click()
    await client.waitUntilWindowLoaded()

    client.element('#save-config').click()
    await client.waitUntilWindowLoaded()

    await client.waitUntil(async () => (await client.getText('#node-status-label') === 'Off'), 5000,
      'Timed out waiting for Node Status to switch to \'Off\' after switching to \'Serving\'')
    assert.strictEqual(await uiInterface.verifyNodeDown(10000), true, 'node did not go down after saving config while node running.')
    await client.waitUntil(async () => (await indexPage.nodeDescriptor.getText() === ''), 5000,
      'Timed out waiting for Node Descriptor to clear')
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

  get networkSettings () {
    return this.client.element('#network-settings-menu')
  }

  get nodeDescriptor () {
    return this.client.element('#node-descriptor')
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

  get blockchainServiceUrl () {
    return this.client.element('#blockchain-service-url')
  }

  get chainName () {
    return this.client.element('#chain-name')
  }

  get saveConfig () {
    return this.client.element('#save-config')
  }

  constructor (client) {
    this.client = client
  }
}
