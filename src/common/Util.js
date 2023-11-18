const debug = require('debug')('prismarine-auth')
const crypto = require('crypto')

async function checkStatus (res) {
  if (res.ok) { 
    return res.json()
  } else {
    const resp = await res.text()
    console.log(`${res.status} ${res.statusText} ${resp}`)
  }
}

function createHash (input) {
  return crypto.createHash('sha1').update(input ?? '', 'binary').digest('hex').substr(0, 6)
}

module.exports = { checkStatus, createHash }
