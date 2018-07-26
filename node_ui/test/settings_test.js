// Copyright (c) 2017-2018, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const td = require('testdouble')
const util = require('./test_utilities')

describe('Settings', function () {
  let subject
  let mockApp, mockSettingsButton, mockSettingsMenu, mockQuitButton, mockMainBody, mockEvent

  beforeEach(function () {
    mockApp = td.object('App')
    td.replace('electron', {
      remote: {
        app: mockApp
      }
    })

    subject = require('../render-process/settings')

    mockMainBody = util.createMockUIElement()
    mockSettingsButton = util.createMockUIElement()
    mockSettingsMenu = util.createMockUIElement('settings-menu--inactive')
    mockQuitButton = util.createMockUIElement()
    mockSettingsMenu.contains = td.function()
    td.when(mockSettingsMenu.contains(mockQuitButton)).thenReturn(true)

    subject.bind(mockMainBody, mockSettingsMenu, mockSettingsButton, mockQuitButton)
  })

  afterEach(function () {
    td.reset()
  })

  describe('clicking the settings button', function () {
    beforeEach(function () {
      mockSettingsButton.onclick()
    })

    it('opens settings menu', function () {
      assert(mockSettingsMenu.classList.contains('settings-menu--active'))
      assert(!mockSettingsMenu.classList.contains('settings-menu--inactive'))
    })

    describe('clicking quit', function () {
      beforeEach(function () {
        mockQuitButton.onclick()
      })

      it('calls app quit', function () {
        td.verify(mockApp.quit())
      })
    })

    describe('clicking the settings button again', function () {
      beforeEach(function () {
        mockSettingsButton.onclick()
      })

      it('closes the settings menu', function () {
        assert(mockSettingsMenu.classList.contains('settings-menu--inactive'))
        assert(!mockSettingsMenu.classList.contains('settings-menu--active'))
      })
    })

    describe('main body onclick', function () {
      describe('clicking the body', function () {
        beforeEach(function () {
          mockEvent = {target: mockMainBody}
          mockMainBody.onclick(mockEvent)
        })

        it('closes the settings menu', function () {
          assert(mockSettingsMenu.classList.contains('settings-menu--inactive'))
          assert(!mockSettingsMenu.classList.contains('settings-menu--active'))
        })
      })

      describe('clicking the menu', function () {
        beforeEach(function () {
          mockEvent = { target: mockSettingsMenu }
          mockMainBody.onclick(mockEvent)
        })

        it('does not close the settings menu', function () {
          assert(mockSettingsMenu.classList.contains('settings-menu--active'))
          assert(!mockSettingsMenu.classList.contains('settings-menu--inactive'))
        })
      })

      describe('clicking a menu child', function () {
        beforeEach(function () {
          mockEvent = { target: mockQuitButton }
          mockMainBody.onclick(mockEvent)
        })

        it('does not close the settings menu', function () {
          assert(mockSettingsMenu.classList.contains('settings-menu--active'))
          assert(!mockSettingsMenu.classList.contains('settings-menu--inactive'))
        })
      })

      describe('clicking the settings button', function () {
        beforeEach(function () {
          mockEvent = { target: mockSettingsButton }
          mockMainBody.onclick(mockEvent)
        })

        it('does not close the settings menu', function () {
          assert(mockSettingsMenu.classList.contains('settings-menu--active'))
          assert(!mockSettingsMenu.classList.contains('settings-menu--inactive'))
        })
      })
    })
  })
})
