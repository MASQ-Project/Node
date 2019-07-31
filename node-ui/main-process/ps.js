// Copyright (c) Sindre Sorhus <sindresorhus@gmail.com> (sindresorhus.com)
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

const path = require('path')
const childProcess = require('child_process')

function win () {
  const startsWith = function (string, prefix) {
    const actualPrefix = string.substr(0, prefix.length)
    return actualPrefix === prefix
  }

  return new Promise((resolve, reject) =>
    childProcess.exec('wmic path win32_process get Commandline, name, ProcessId -format:list', (error, stdout) => {
      if (error) {
        reject(error)
      } else {
        const processes = []
        let pid = null
        let name = ''
        let cmd = ''
        for (let line of stdout.trim().split('\n').slice(1)) {
          line = line.trim()
          if (startsWith(line, 'CommandLine=')) {
            cmd = line.substr('CommandLine='.length)
          } else if (startsWith(line, 'Name=')) {
            name = line.substr('Name='.length)
          } else if (startsWith(line, 'ProcessId=')) {
            const strPid = line.substr('ProcessId='.length)
            pid = Number.parseInt(strPid, 10)
          } else {
            if (pid != null) {
              processes.push({
                pid: pid,
                name: name,
                cmd: cmd
              })
              pid = null
              name = ''
              cmd = ''
            }
          }
        }
        resolve(processes)
      }
    })
  )
}

function def (options = {}) {
  const ret = {}
  const flags = (options.all === false ? '' : 'a') + 'wwxo'

  return Promise.all(['comm', 'args'].map(cmd => {
    return new Promise((resolve, reject) =>
      childProcess.execFile('ps', [flags, `pid,${cmd}`], (error, stdout) => {
        if (error) {
          reject(error)
        } else {
          for (let line of stdout.trim().split('\n').slice(1)) {
            line = line.trim()
            const [pid] = line.split(' ', 1)
            const val = line.slice(pid.length + 1).trim()

            if (ret[pid] === undefined) {
              ret[pid] = {}
            }

            ret[pid][cmd] = val
          }
          resolve()
        }
      })
    )
  }
  )).then(() => {
    return Object.keys(ret).filter(x => ret[x].comm && ret[x].args).map(x => {
      return {
        pid: Number.parseInt(x, 10),
        name: path.basename(ret[x].comm),
        cmd: ret[x].args
      }
    })
  })
}

module.exports = process.platform === 'win32' ? win : def
