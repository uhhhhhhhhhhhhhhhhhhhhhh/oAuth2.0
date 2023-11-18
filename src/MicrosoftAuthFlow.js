const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const debug = require('debug')('prismarine-auth')

const { createHash } = require('./common/Util')
const { Endpoints, msalConfig } = require('./common/Constants')
const FileCache = require('./common/cache/FileCache')

const LiveTokenManager = require('./TokenManagers/LiveTokenManager')
const JavaTokenManager = require('./TokenManagers/MinecraftJavaTokenManager')
const XboxTokenManager = require('./TokenManagers/XboxTokenManager')
const MsaTokenManager = require('./TokenManagers/MsaTokenManager')

async function retry (methodFn, beforeRetry, times) {
  while (times--) {
    if (times !== 0) {
      try { return await methodFn() } catch (e) { if (e instanceof URIError) { throw e } else { debug(e) } }
      await new Promise(resolve => setTimeout(resolve, 2000))
      await beforeRetry()
    } else {
      return await methodFn()
    }
  }
}

class MicrosoftAuthFlow {
  constructor (username = '', cache = __dirname, options, codeCallback) {
    this.username = username
    if (options && !options.flow) {
      throw new Error("Missing 'flow' argument in options. See docs for more information.")
    }
    this.options = options || { flow: 'msal' }
    this.initTokenManagers(username, cache)
    this.codeCallback = codeCallback
  }

  initTokenManagers (username, cache) {
    if (typeof cache !== 'function') {
      let cachePath = cache

      debug(`Using cache path: ${cachePath}`)

      try {
        if (!fs.existsSync(cachePath)) {
          fs.mkdirSync(cachePath, { recursive: true })
        }
      } catch (e) {
        console.log('Failed to open cache dir', e)
        cachePath = __dirname
      }

      cache = ({ cacheName, username }) => {
        const hash = createHash(username)
        return new FileCache(path.join(cachePath, `./${hash}_${cacheName}-cache.json`))
      }
    }

    if (this.options.flow === 'live' || this.options.flow === 'sisu') {
      if (!this.options.authTitle) throw new Error(`Please specify an "authTitle" in Authflow constructor when using ${this.options.flow} flow`)
      this.msa = new LiveTokenManager(this.options.authTitle, ['service::user.auth.xboxlive.com::MBI_SSL'], cache({ cacheName: this.options.flow, username }))
      this.doTitleAuth = true
    } else if (this.options.flow === 'msal') {
      const config = Object.assign({ ...msalConfig }, this.options.authTitle ? { auth: { ...msalConfig.auth, clientId: this.options.authTitle } } : {})
      this.msa = new MsaTokenManager(config, ['XboxLive.signin', 'offline_access'], cache({ cacheName: 'msal', username }))
    } else {
      throw new Error(`Unknown flow: ${this.options.flow} (expected "live", "sisu", or "msal")`)
    }

    const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })
    this.xbl = new XboxTokenManager(keyPair, cache({ cacheName: 'xbl', username }))
    this.mca = new JavaTokenManager(cache({ cacheName: 'mca', username }))
  }

  static resetTokenCaches (cache) {
    if (!cache) throw new Error('You must provide a cache directory to reset.')
    try {
      if (fs.existsSync(cache)) {
        fs.rmSync(cache, { recursive: true })
        return true
      }
    } catch (e) {
      console.log('Failed to clear cache dir', e)
      return false
    }
  }

  async getMsaToken () {
    const ret = await this.msa.authDeviceCode((response) => {
      if (this.codeCallback) return this.codeCallback(response)
    })

    if (ret.account) {
      console.info(`[msa] Signed in as ${ret.account.username}`)
    } else { 
      console.info('[msa] Signed in with Microsoft')
    }

    console.log('[msa] got auth result', ret)
    return ret.accessToken
  }

  async getXboxToken (relyingParty = this.options.relyingParty || Endpoints.XboxRelyingParty) {
    const options = { ...this.options, relyingParty }

    const { xstsToken, userToken, deviceToken, titleToken } = await this.xbl.getCachedTokens(relyingParty)

    if (xstsToken.valid) {
      console.log('[xbl] Using existing XSTS token')
      return xstsToken.data
    }

    if (options.password) {
      console.log('[xbl] password is present, trying to authenticate using xboxreplay/xboxlive-auth')
      const xsts = await this.xbl.doReplayAuth(this.username, options.password, options)
      return xsts
    }

    console.log('[xbl] Need to obtain tokens')

    return await retry(async () => {
      const msaToken = await this.getMsaToken()

      if (options.flow === 'sisu' && (!userToken.valid || !deviceToken.valid || !titleToken.valid)) {
        console.log(`[xbl] Sisu flow selected, trying to authenticate with authTitle ID ${options.authTitle}`)
        const dt = await this.xbl.getDeviceToken(options)
        const sisu = await this.xbl.doSisuAuth(msaToken, dt, options)
        return sisu
      }

      console.log("Other way")

      const ut = userToken.token ?? await this.xbl.getUserToken(msaToken, options.flow === 'msal')
      const dt = deviceToken.token ?? await this.xbl.getDeviceToken(options)
      const tt = titleToken.token ?? (this.doTitleAuth ? await this.xbl.getTitleToken(msaToken, dt) : undefined)

      const xsts = await this.xbl.getXSTSToken({ userToken: ut, deviceToken: dt, titleToken: tt }, options)
      return xsts
    }, () => { this.msa.forceRefresh = true }, 2)
  }

  async getMinecraftJavaToken (options = {}) {
    const response = { token: '', entitlements: {}, profile: {} }
    if (await this.mca.verifyTokens()) {
      debug('[mc] Using existing tokens')
      const { token } = await this.mca.getCachedAccessToken()
      response.token = token
    } else {
      debug('[mc] Need to obtain tokens')
      await retry(async () => {
        const xsts = await this.getXboxToken(Endpoints.PCXSTSRelyingParty)
        debug('[xbl] xsts data', xsts)
        response.token = await this.mca.getAccessToken(xsts)
      }, () => { this.xbl.forceRefresh = true }, 2)
    }

    if (options.fetchEntitlements) {
      response.entitlements = await this.mca.fetchEntitlements(response.token).catch(e => debug('Failed to obtain entitlement data', e))
    }
    if (options.fetchProfile) {
      response.profile = await this.mca.fetchProfile(response.token).catch(e => debug('Failed to obtain profile data', e))
    }
    if (options.fetchCertificates) {
      response.certificates = await this.mca.fetchCertificates(response.token).catch(e => debug('Failed to obtain keypair data', e))
    }

    return response
  }
}

MicrosoftAuthFlow

module.exports = MicrosoftAuthFlow
