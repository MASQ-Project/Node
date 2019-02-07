// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const td = require('testdouble')

describe('Renderer', () => {
  let mockIpcRenderer, mockShell, mockNodeActuator, mockDocument, mockSettings, mockUrl1, mockUrl2, mockLink1,
    mockLink2, eventCaptor, mockEvent1, mockEvent2, mockApp

  let killFunctionCaptor

  beforeEach(() => {
    mockIpcRenderer = td.object(['on'])
    mockShell = td.object(['openExternal'])
    td.replace('electron', {
      ipcRenderer: mockIpcRenderer,
      shell: mockShell,
      remote: {
        app: mockApp
      }
    })

    mockNodeActuator = td.replace('../render-process/node_actuator')
    mockSettings = td.replace('../render-process/settings')
    mockDocument = td.replace('../wrappers/document_wrapper')
    killFunctionCaptor = td.matchers.captor()

    td.when(mockDocument.getElementById('off')).thenReturn('Off')
    td.when(mockDocument.getElementById('serving')).thenReturn('Serving')
    td.when(mockDocument.getElementById('consuming')).thenReturn('Consuming')
    td.when(mockDocument.getElementById('settings-menu')).thenReturn('Settings Menu')
    td.when(mockDocument.getElementById('settings-button')).thenReturn('Settings Button')
    td.when(mockDocument.getElementById('settings-menu-quit')).thenReturn('Quit Button')
    td.when(mockDocument.getElementById('main')).thenReturn('Main Body')

    eventCaptor = td.matchers.captor()
    mockEvent1 = td.object()
    mockEvent2 = td.object()
    mockUrl1 = td.object('1')
    td.when(mockUrl1.indexOf('http')).thenReturn(0)
    mockUrl2 = td.object('2')
    td.when(mockUrl2.indexOf('http')).thenReturn(0)
    mockLink1 = td.object()
    td.when(mockLink1.getAttribute('href')).thenReturn(mockUrl1)
    mockLink2 = td.object()
    td.when(mockLink2.getAttribute('href')).thenReturn(mockUrl2)
    td.when(mockDocument.querySelectorAll('div[href]')).thenReturn([mockLink1, mockLink2])

    require('../render-process/renderer')
  })

  afterEach(() => {
    td.reset()
  })

  it('binds the ui elements', () => {
    td.verify(mockNodeActuator.bind('Off', 'Serving', 'Consuming'))
    td.verify(mockSettings.bind('Main Body', 'Settings Menu', 'Settings Button', 'Quit Button'))
  })

  describe('sets all links', () => {
    beforeEach(() => {
      td.verify(mockLink1.addEventListener('click', eventCaptor.capture()))
      td.verify(mockLink2.addEventListener('click', eventCaptor.capture()))

      eventCaptor.values[0](mockEvent1)
      eventCaptor.values[1](mockEvent2)
    })

    it('to open externally', () => {
      let urlCaptor = td.matchers.captor()
      td.verify(mockShell.openExternal(urlCaptor.capture()))
      td.verify(mockShell.openExternal(urlCaptor.capture()))
      assert.strictEqual(urlCaptor.values[0], mockUrl1)
      assert.strictEqual(urlCaptor.values[1], mockUrl2)
      td.verify(mockEvent1.preventDefault())
      td.verify(mockEvent2.preventDefault())
    })
  })

  describe('receiving a kill-substratum-node message', () => {
    beforeEach(() => {
      td.verify(mockIpcRenderer.on('kill-substratum-node', killFunctionCaptor.capture()))
      killFunctionCaptor.value()
    })

    it('reverts the dns', () => {
      td.verify(mockNodeActuator.shutdown())
    })
  })
})
