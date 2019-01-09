// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

module.exports = (() => {
  const {app} = require('electron').remote
  let settingsButton, settingsMenu, settingsQuitButton, body

  function bind (_body, _settingsMenu, _settingsButton, _settingsQuitButton) {
    settingsButton = _settingsButton
    settingsMenu = _settingsMenu
    settingsQuitButton = _settingsQuitButton
    body = _body

    settingsButton.onclick = () => {
      toggleSettings()
    }

    settingsQuitButton.onclick = () => {
      app.quit()
    }

    body.onclick = function (e) {
      if (isNotSettingsMenu(e.target) && isNotSettingsButton(e.target) && menuDoesNotContain(e.target)) {
        closeSettings()
      }
    }
  }

  function toggleSettings () {
    if (settingsOpened()) {
      closeSettings()
    } else {
      openSettings()
    }
  }

  function isNotSettingsMenu (thing) {
    return !(settingsMenu === thing)
  }

  function isNotSettingsButton (thing) {
    return !(settingsButton === thing)
  }

  function menuDoesNotContain (thing) {
    return !(settingsMenu.contains(thing))
  }

  function settingsOpened () {
    return settingsMenu.classList.contains('settings-menu--active')
  }

  function closeSettings () {
    settingsMenu.classList.remove('settings-menu--active')
    settingsMenu.classList.add('settings-menu--inactive')
  }

  function openSettings () {
    settingsMenu.classList.remove('settings-menu--inactive')
    settingsMenu.classList.add('settings-menu--active')
  }

  return {
    bind: bind
  }
})()
