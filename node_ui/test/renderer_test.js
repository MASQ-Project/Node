// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const td = require('testdouble')

describe('Renderer', function () {
  let mockIpcRenderer, mockNodeActuator, mockDocument

  let killFunctionCaptor

  beforeEach(function () {
    mockIpcRenderer = td.object(['on'])
    td.replace('electron', {
      ipcRenderer: mockIpcRenderer
    })

    mockNodeActuator = td.replace('../render-process/node_actuator')
    mockDocument = td.replace('../wrappers/document_wrapper')
    killFunctionCaptor = td.matchers.captor()

    td.when(mockDocument.getElementById('node-status-label')).thenReturn('Label')
    td.when(mockDocument.getElementById('off')).thenReturn('Off')
    td.when(mockDocument.getElementById('serving')).thenReturn('Serving')
    td.when(mockDocument.getElementById('consuming')).thenReturn('Consuming')

    require('../render-process/renderer')
  })

  afterEach(function () {
    td.reset()
  })

  it('binds the ui elements', function () {
    td.verify(mockNodeActuator.bind('Label', 'Off', 'Serving', 'Consuming'))
  })

  describe('receiving a kill-substratum-node message', function () {
    beforeEach(function () {
      td.verify(mockIpcRenderer.on('kill-substratum-node', killFunctionCaptor.capture()))
      killFunctionCaptor.value()
    })

    it('reverts the dns', function () {
      td.verify(mockNodeActuator.shutdown())
    })
  })
})
