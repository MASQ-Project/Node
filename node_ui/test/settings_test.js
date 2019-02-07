// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe beforeEach afterEach it */

const assert = require('assert')
const td = require('testdouble')
const util = require('./test_utilities')

describe('Settings', () => {
  let subject
  let mockApp, mockSettingsButton, mockSettingsMenu, mockQuitButton, mockMainBody, mockEvent

  beforeEach(() => {
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

  afterEach(() => {
    td.reset()
  })

  describe('clicking the settings button', () => {
    beforeEach(() => {
      mockSettingsButton.onclick()
    })

    it('opens settings menu', () => {
      assert(mockSettingsMenu.classList.contains('settings-menu--active'))
      assert(!mockSettingsMenu.classList.contains('settings-menu--inactive'))
    })

    describe('clicking quit', () => {
      beforeEach(() => {
        mockQuitButton.onclick()
      })

      it('calls app quit', () => {
        td.verify(mockApp.quit())
      })
    })

    describe('clicking the settings button again', () => {
      beforeEach(() => {
        mockSettingsButton.onclick()
      })

      it('closes the settings menu', () => {
        assert(mockSettingsMenu.classList.contains('settings-menu--inactive'))
        assert(!mockSettingsMenu.classList.contains('settings-menu--active'))
      })
    })

    describe('main body onclick', () => {
      describe('clicking the body', () => {
        beforeEach(() => {
          mockEvent = {target: mockMainBody}
          mockMainBody.onclick(mockEvent)
        })

        it('closes the settings menu', () => {
          assert(mockSettingsMenu.classList.contains('settings-menu--inactive'))
          assert(!mockSettingsMenu.classList.contains('settings-menu--active'))
        })
      })

      describe('clicking the menu', () => {
        beforeEach(() => {
          mockEvent = { target: mockSettingsMenu }
          mockMainBody.onclick(mockEvent)
        })

        it('does not close the settings menu', () => {
          assert(mockSettingsMenu.classList.contains('settings-menu--active'))
          assert(!mockSettingsMenu.classList.contains('settings-menu--inactive'))
        })
      })

      describe('clicking a menu child', () => {
        beforeEach(() => {
          mockEvent = { target: mockQuitButton }
          mockMainBody.onclick(mockEvent)
        })

        it('does not close the settings menu', () => {
          assert(mockSettingsMenu.classList.contains('settings-menu--active'))
          assert(!mockSettingsMenu.classList.contains('settings-menu--inactive'))
        })
      })

      describe('clicking the settings button', () => {
        beforeEach(() => {
          mockEvent = { target: mockSettingsButton }
          mockMainBody.onclick(mockEvent)
        })

        it('does not close the settings menu', () => {
          assert(mockSettingsMenu.classList.contains('settings-menu--active'))
          assert(!mockSettingsMenu.classList.contains('settings-menu--inactive'))
        })
      })
    })
  })
})
