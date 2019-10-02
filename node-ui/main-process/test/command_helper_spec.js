// Copyright (c) 2017-2019, Substratum LLC (https://substratum.net) and/or its affiliates. All rights reserved.

/* global describe expect beforeEach afterEach it */

const fs = require('fs')
const generatedBasePath = 'main-process/generated/command_helper_spec'
const commandHelper = require('../src/command_helper')

function ensureCleanDirectoryExists (basePath, namespace) {
  const dirName = basePath + '/' + namespace
  const myRmDirent = (basePath, dirent) => {
    const fullPath = basePath + '/' + dirent.name
    if (dirent.isDirectory()) {
      myRmDir(fullPath)
    } else {
      fs.unlinkSync(fullPath)
    }
  }
  const myRmDir = (dirPath) => {
    if (fs.existsSync(dirPath)) {
      fs.readdirSync(dirPath, { withFileTypes: true }).forEach((dirent) => {
        myRmDirent(dirPath, dirent)
      })
      fs.rmdirSync(dirPath)
    }
  }
  myRmDir(dirName)
  fs.mkdirSync(dirName, { recursive: true })
  if (process.platform !== 'win32') {
    fs.chownSync(basePath, parseInt(process.env.SUDO_UID), parseInt(process.env.SUDO_GID))
    fs.chownSync(dirName, parseInt(process.env.SUDO_UID), parseInt(process.env.SUDO_GID))
  }
  return dirName
}

describe('When the Node configuration is retrieved', () => {
  let configuration
  let oldDataDirectory

  beforeEach(() => {
    const dataDir = ensureCleanDirectoryExists(generatedBasePath, 'node_configuration_retrieved')
    oldDataDirectory = process.env.SUB_DATA_DIRECTORY
    process.env.SUB_DATA_DIRECTORY = dataDir
    configuration = commandHelper.getNodeConfiguration()
  })

  afterEach(() => {
    if (oldDataDirectory) {
      process.env.SUB_DATA_DIRECTORY = oldDataDirectory
    } else {
      delete process.env.SUB_DATA_DIRECTORY
    }
  })

  it('it contains useful values', () => {
    expect(parseSemVer(configuration.schemaVersion)).toBeGreaterThanOrEqual(parseSemVer('0.0.9'))
    expect(parseInt(configuration.startBlock)).toBeGreaterThanOrEqual(4647463)
  })
})

function parseSemVer (semver) {
  const parts = semver.split('.')
  let value = 0
  let multiplier = 1
  while (parts.length > 0) {
    value *= multiplier
    multiplier *= 100
    value += parseInt(parts[parts.length - 1])
    parts.length -= 1
  }
  return value
}
