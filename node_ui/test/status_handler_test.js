// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const td = require('testdouble')
const assert = require('assert')
const util = require('./test_utilities')

describe('StatusHandler', function () {
  let subject, mockDocument, mockNodeStatusLabel, mockOffButton,
    mockConsumingButton, mockServingButton, mockButtonContainer, mockPsWrapper, mockDnsUtility

  beforeEach(function () {
    mockDocument = td.replace('../wrappers/document_wrapper')
    mockPsWrapper = td.replace('../wrappers/ps_wrapper')
    mockDnsUtility = td.replace('../command-process/dns_utility')
    mockNodeStatusLabel = { innerHTML: '' }
    mockOffButton = util.createMockUIElement()
    mockServingButton = util.createMockUIElement()
    mockConsumingButton = util.createMockUIElement()
    mockButtonContainer = util.createMockUIElement()

    td.when(mockDocument.getElementById('node-status-buttons')).thenReturn(mockButtonContainer)

    subject = require('../handlers/status_handler')
  })

  afterEach(function () {
    td.reset()
  })

  describe('off event', function () {
    beforeEach(function () {
      mockServingButton = util.createMockUIElement('button-active')
      mockConsumingButton = util.createMockUIElement('button-active')

      td.when(mockDocument.getElementById('node-status-label')).thenReturn(mockNodeStatusLabel)
      td.when(mockDocument.getElementById('off')).thenReturn(mockOffButton)
      td.when(mockDocument.querySelectorAll('.button-active')).thenReturn([mockServingButton, mockConsumingButton])

      subject.emit('off')
    })

    it('sets status label to off', function () {
      assert.strictEqual(mockNodeStatusLabel.innerHTML, 'Off')
    })

    it('adds button-active class to off button', function () {
      assert(mockOffButton.classList.contains('button-active'), 'Off should be active')
    })

    it('removes button-active class from serving and consuming button', function () {
      assert(!mockServingButton.classList.contains('button-active'), 'Serving should not be active')
      assert(!mockConsumingButton.classList.contains('button-active'), 'Consuming should not be active')
    })
  })

  describe('serving event', function () {
    beforeEach(function () {
      mockOffButton = util.createMockUIElement('button-active')
      mockConsumingButton = util.createMockUIElement('button-active')

      td.when(mockDocument.getElementById('node-status-label')).thenReturn(mockNodeStatusLabel)
      td.when(mockDocument.getElementById('serving')).thenReturn(mockServingButton)
      td.when(mockDocument.querySelectorAll('.button-active')).thenReturn([mockOffButton, mockConsumingButton])

      subject.emit('serving')
    })

    it('sets status label to Serving', function () {
      assert.strictEqual(mockNodeStatusLabel.innerHTML, 'Serving')
    })

    it('adds button-active class to serving button', function f () {
      assert(mockServingButton.classList.contains('button-active'), 'Serving should be active')
    })

    it('removes button-active class from off and consuming button', function () {
      assert(!mockOffButton.classList.contains('button-active'), 'Off should not be active')
      assert(!mockConsumingButton.classList.contains('button-active'), 'Consuming should not be active')
    })
  })

  describe('consuming event', function () {
    beforeEach(function () {
      mockServingButton = util.createMockUIElement('button-active')
      mockOffButton = util.createMockUIElement('button-active')

      td.when(mockDocument.getElementById('node-status-label')).thenReturn(mockNodeStatusLabel)
      td.when(mockDocument.getElementById('consuming')).thenReturn(mockConsumingButton)
      td.when(mockDocument.querySelectorAll('.button-active')).thenReturn([mockServingButton, mockOffButton])

      subject.emit('consuming')
    })

    it('sets status label to Consuming', function () {
      assert.strictEqual(mockNodeStatusLabel.innerHTML, 'Consuming')
    })

    it('adds button-active class to consuming button', function f () {
      assert(mockConsumingButton.classList.contains('button-active'), 'Consuming should be active')
    })

    it('removes button-active class from serving and consuming button', function () {
      assert(!mockServingButton.classList.contains('button-active'), 'Serving should not be active')
      assert(!mockOffButton.classList.contains('button-active'), 'Off should not be active')
    })
  })

  describe('invalid event', function () {
    beforeEach(function () {
      mockServingButton = util.createMockUIElement('button-active')

      td.when(mockDocument.getElementById('node-status-label')).thenReturn(mockNodeStatusLabel)
      td.when(mockDocument.querySelectorAll('.button-active')).thenReturn([mockServingButton])

      subject.emit('invalid')
    })

    it('sets status label to invalid', function () {
      assert.strictEqual(mockNodeStatusLabel.innerHTML, 'An error occurred. Choose a state.')
    })

    it('adds invalid class to button container', function () {
      assert(mockButtonContainer.classList.contains('node-status__actions--invalid'))
    })

    it('removes button-active class from all buttons', function () {
      assert(!mockOffButton.classList.contains('button-active'))
      assert(!mockServingButton.classList.contains('button-active'))
      assert(!mockConsumingButton.classList.contains('button-active'))
    })
  })

  describe('resets invalid', function () {
    beforeEach(function () {
      mockServingButton = util.createMockUIElement('button-active')
      mockButtonContainer = util.createMockUIElement('node-status__actions--invalid')

      td.when(mockDocument.getElementById('node-status-buttons')).thenReturn(mockButtonContainer)
      td.when(mockDocument.getElementById('node-status-label')).thenReturn(mockNodeStatusLabel)
      td.when(mockDocument.querySelectorAll('.button-active')).thenReturn([mockServingButton])
    })

    it('off event removes invalid class from button container', function () {
      td.when(mockDocument.getElementById('off')).thenReturn(mockOffButton)
      subject.emit('off')
      assert(!mockButtonContainer.classList.contains('node-status__actions--invalid'))
    })

    it('serving event removes invalid class from button container', function () {
      td.when(mockDocument.getElementById('serving')).thenReturn(mockServingButton)
      subject.emit('serving')
      assert(!mockButtonContainer.classList.contains('node-status__actions--invalid'))
    })

    it('consuming event removes invalid class from button container', function () {
      td.when(mockDocument.getElementById('consuming')).thenReturn(mockConsumingButton)
      subject.emit('consuming')
      assert(!mockButtonContainer.classList.contains('node-status__actions--invalid'))
    })
  })

  describe('init status', function () {
    beforeEach(function () {
      td.when(mockDocument.getElementById('node-status-label')).thenReturn(mockNodeStatusLabel)
    })

    describe('consuming', function () {
      beforeEach(function () {
        let mockProcessList = [ {}, {pid: 1234} ]

        td.when(mockPsWrapper.findByName('SubstratumNode')).thenCallback(mockProcessList)
        td.when(mockDnsUtility.getStatus()).thenReturn('subverted')

        mockServingButton = util.createMockUIElement('button-active')
        td.when(mockDocument.getElementById('consuming')).thenReturn(mockConsumingButton)
        td.when(mockDocument.querySelectorAll('.button-active')).thenReturn([mockServingButton, mockOffButton])

        subject.emit('init-status')
      })

      it('sets status label to Consuming', function () {
        assert.strictEqual(mockNodeStatusLabel.innerHTML, 'Consuming')
      })

      it('adds button-active class to consuming button', function f () {
        assert(mockConsumingButton.classList.contains('button-active'), 'Consuming should be active')
      })

      it('removes button-active class from serving and off button', function () {
        assert(!mockServingButton.classList.contains('button-active'), 'Serving should not be active')
        assert(!mockOffButton.classList.contains('button-active'), 'Off should not be active')
      })
    })

    describe('serving', function () {
      beforeEach(function () {
        let mockProcessList = [ {}, {pid: 1234} ]

        td.when(mockPsWrapper.findByName('SubstratumNode')).thenCallback(mockProcessList)
        td.when(mockDnsUtility.getStatus()).thenReturn('reverted')

        mockOffButton = util.createMockUIElement('button-active')
        td.when(mockDocument.getElementById('serving')).thenReturn(mockServingButton)
        td.when(mockDocument.querySelectorAll('.button-active')).thenReturn([mockConsumingButton, mockOffButton])

        subject.emit('init-status')
      })

      it('sets status label to Serving', function () {
        assert.strictEqual(mockNodeStatusLabel.innerHTML, 'Serving')
      })

      it('adds button-active class to serving button', function f () {
        assert(mockServingButton.classList.contains('button-active'), 'Serving should be active')
      })

      it('removes button-active class from off and consuming button', function () {
        assert(!mockOffButton.classList.contains('button-active'), 'Off should not be active')
        assert(!mockConsumingButton.classList.contains('button-active'), 'Consuming should not be active')
      })
    })

    describe('invalid', function () {
      beforeEach(function () {
        mockServingButton = util.createMockUIElement('button-active')

        td.when(mockPsWrapper.findByName('SubstratumNode')).thenCallback([])
        td.when(mockDnsUtility.getStatus()).thenReturn('subverted')
        td.when(mockDocument.querySelectorAll('.button-active')).thenReturn([mockServingButton])

        subject.emit('init-status')
      })

      it('sets status label to invalid', function () {
        assert.strictEqual(mockNodeStatusLabel.innerHTML, 'An error occurred. Choose a state.')
      })

      it('adds invalid class to button container', function () {
        assert(mockButtonContainer.classList.contains('node-status__actions--invalid'))
      })

      it('removes button-active class from all buttons', function () {
        assert(!mockOffButton.classList.contains('button-active'))
        assert(!mockServingButton.classList.contains('button-active'))
        assert(!mockConsumingButton.classList.contains('button-active'))
      })
    })

    describe('off', function () {
      beforeEach(function () {
        td.when(mockPsWrapper.findByName('SubstratumNode')).thenCallback([])
        td.when(mockDnsUtility.getStatus()).thenReturn('reverted')

        mockServingButton = util.createMockUIElement('button-active')
        td.when(mockDocument.getElementById('off')).thenReturn(mockOffButton)
        td.when(mockDocument.querySelectorAll('.button-active')).thenReturn([mockServingButton, mockConsumingButton])

        subject.emit('init-status')
      })

      it('sets status label to Consuming', function () {
        assert.strictEqual(mockNodeStatusLabel.innerHTML, 'Off')
      })

      it('adds button-active class to consuming button', function f () {
        assert(mockOffButton.classList.contains('button-active'), 'Off should be active')
      })

      it('removes button-active class from serving and off button', function () {
        assert(!mockServingButton.classList.contains('button-active'), 'Serving should not be active')
        assert(!mockConsumingButton.classList.contains('button-active'), 'Consuming should not be active')
      })
    })
  })
})
