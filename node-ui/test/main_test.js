// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach it afterEach */

const td = require('testdouble')

describe('shutting down', () => {
  let subject, mockApp, mockDialog, mockEvent, mainWindowOnClose, MockNodeActuator, appOnReady

  beforeEach(() => {
    mockEvent = td.object(['preventDefault'])
    mockApp = td.object(['on', 'quit'])
    mockDialog = td.object(['showErrorBox'])
    MockNodeActuator = td.constructor(['shutdown'])
    td.replace('../main-process/node_actuator', MockNodeActuator)

    const MockBrowserWindow = td.constructor(['on', 'loadURL'])
    mainWindowOnClose = td.matchers.captor()
    td.when(MockBrowserWindow.prototype.on('close', mainWindowOnClose.capture())).thenReturn()

    appOnReady = td.matchers.captor()
    td.when(mockApp.on('ready', appOnReady.capture())).thenReturn()

    td.replace('electron', {
      app: mockApp,
      BrowserWindow: MockBrowserWindow,
      dialog: mockDialog,
      ipcMain: td.object()})
    subject = require('../main')
  })

  afterEach(() => {
    td.reset()
  })

  describe('successfully', () => {
    beforeEach(async () => {
      td.when(MockNodeActuator.prototype.shutdown()).thenResolve()
      appOnReady.value()

      await mainWindowOnClose.value(mockEvent)
    })

    it('prevents the default close event behavior', async () => {
      td.verify(mockEvent.preventDefault(), { times: 1 })
    })

    it('quits the app', async () => {
      td.verify(mockApp.quit(), { times: 1 })
    })

    describe('when the app is already quitting', () => {
      beforeEach(async () => {
        await mainWindowOnClose.value(mockEvent)
      })

      it('does not prevent the default close event behavior', () => {
        td.verify(mockEvent.preventDefault(), { times: 1 })
      })

      it('does not call quit again', () => {
        td.verify(mockApp.quit(), { times: 1 })
      })
    })
  })

  describe('unsuccessfully', () => {
    beforeEach(async () => {
      td.when(MockNodeActuator.prototype.shutdown()).thenReject('beggin for help')
      appOnReady.value()

      await mainWindowOnClose.value(mockEvent)
    })

    it('shows an error dialog', () => {
      td.verify(mockDialog.showErrorBox(
        "Error shutting down Substratum Node.",
        'Could not shut down Substratum Node.  You may need to kill it manually.\n\nReason: "beggin for help"'))
    })

    it('quits the app', () => {
      td.verify(mockApp.quit())
    })

    describe('when the app is already quitting', () => {
      beforeEach(async () => {
        await mainWindowOnClose.value(mockEvent)
      })

      it('does not prevent the default close event behavior', () => {
        td.verify(mockEvent.preventDefault(), { times: 1 })
      })

      it('does not call quit again', () => {
        td.verify(mockApp.quit(), { times: 1 })
      })
    })
  })
})
