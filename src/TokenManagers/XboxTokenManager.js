const crypto = require('crypto')

const XboxLiveAuth = require('@xboxreplay/xboxlive-auth')
const debug = require('debug')('prismarine-auth')
const { SmartBuffer } = require('smart-buffer')
const { exportJWK } = require('jose')
const fetch = require('node-fetch')

const { Endpoints, xboxLiveErrors } = require('../common/Constants')
const { checkStatus, createHash } = require('../common/Util')

const UUID = require('uuid-1345')
const nextUUID = () => UUID.v3({ namespace: '6ba7b811-9dad-11d1-80b4-00c04fd430c8', name: Date.now().toString() })

const checkIfValid = (expires) => {
  const remainingMs = new Date(expires) - Date.now()
  const valid = remainingMs > 1000
  return valid
}

class XboxTokenManager {
  constructor (ecKey, cache) {
    this.key = ecKey
    exportJWK(ecKey.publicKey).then(jwk => {
      this.jwk = { ...jwk, alg: 'ES256', use: 'sig' }
    })
    this.cache = cache

    this.headers = { 'Cache-Control': 'no-store, must-revalidate, no-cache', 'x-xbl-contract-version': 1 }
  }

  async setCachedToken (data) {
    await this.cache.setCachedPartial(data)
  }

  async getCachedTokens (relyingParty) {
    const cachedTokens = await this.cache.getCached()

    const xstsHash = createHash(relyingParty)

    const result = {}

    for (const token of ['userToken', 'titleToken', 'deviceToken']) {
      const cached = cachedTokens[token]
      result[token] = cached && checkIfValid(cached.NotAfter)
        ? { valid: true, token: cached.Token, data: cached }
        : { valid: false }
    }
    result.xstsToken = cachedTokens[xstsHash] && checkIfValid(cachedTokens[xstsHash].expiresOn)
      ? { valid: true, data: cachedTokens[xstsHash] }
      : { valid: false }

    return result
  }

  checkTokenError (errorCode, response) {
    if (errorCode in xboxLiveErrors) throw new Error(xboxLiveErrors[errorCode])
    else throw new Error(`Xbox Live authentication failed to obtain a XSTS token. XErr: ${errorCode}\n${JSON.stringify(response)}`)
  }

  async getUserToken (accessToken, azure) {
    debug('[xbl] obtaining xbox token with ms token', accessToken)
    const preamble = azure ? 'd=' : 't='

    const payload = {
      RelyingParty: 'http://auth.xboxlive.com',
      TokenType: 'JWT',
      Properties: {
        AuthMethod: 'RPS',
        SiteName: 'user.auth.xboxlive.com',
        RpsTicket: `${preamble}${accessToken}`
      }
    }

    const body = JSON.stringify(payload)
    const signature = this.sign(Endpoints.XboxUserAuth, '', body).toString('base64')
    const headers = { ...this.headers, signature, 'Content-Type': 'application/json', accept: 'application/json', 'x-xbl-contract-version': '2' }

    const ret = await fetch(Endpoints.XboxUserAuth, { method: 'post', headers, body }).then(checkStatus)

    await this.setCachedToken({ userToken: ret })

    debug('[xbl] user token:', ret)
    return ret.Token
  }

  sign (url, authorizationToken, payload) {
    const windowsTimestamp = (BigInt((Date.now() / 1000) | 0) + 11644473600n) * 10000000n
    const pathAndQuery = new URL(url).pathname

    const allocSize = /* sig */ 5 + /* ts */ 9 + /* POST */ 5 + pathAndQuery.length + 1 + authorizationToken.length + 1 + payload.length + 1
    const buf = SmartBuffer.fromSize(allocSize)
    buf.writeInt32BE(1) 
    buf.writeUInt8(0)
    buf.writeBigUInt64BE(windowsTimestamp)
    buf.writeUInt8(0) 
    buf.writeStringNT('POST')
    buf.writeStringNT(pathAndQuery)
    buf.writeStringNT(authorizationToken)
    buf.writeStringNT(payload)

    const signature = crypto.sign('SHA256', buf.toBuffer(), { key: this.key.privateKey, dsaEncoding: 'ieee-p1363' })

    const header = SmartBuffer.fromSize(signature.length + 12)
    header.writeInt32BE(1) 
    header.writeBigUInt64BE(windowsTimestamp)
    header.writeBuffer(signature) 

    return header.toBuffer()
  }

  async doReplayAuth (email, password, options = {}) {
    try {
      const preAuthResponse = await XboxLiveAuth.preAuth()
      const logUserResponse = await XboxLiveAuth.logUser(preAuthResponse, { email, password })
      const xblUserToken = await XboxLiveAuth.exchangeRpsTicketForUserToken(logUserResponse.access_token)
      await this.setCachedToken({ userToken: xblUserToken })
      debug('[xbl] user token:', xblUserToken)
      const xsts = await this.getXSTSToken({ userToken: xblUserToken.Token }, options)
      return xsts
    } catch (error) {
      debug('Authentication using a password has failed.')
      debug(error)
      throw error
    }
  }

  async doSisuAuth (accessToken, deviceToken) {
    const payload = {
      AccessToken: 't=' + accessToken,
      AppId: '00000000402b5328',
      DeviceToken: deviceToken,
      Sandbox: 'RETAIL',
      UseModernGamertag: true,
      SiteName: 'user.auth.xboxlive.com',
      RelyingParty: 'rp://api.minecraftservices.com/',
      ProofKey: this.jwk
    }

    const body = JSON.stringify(payload)

    const signature = this.sign(Endpoints.SisuAuthorize, '', body).toString('base64')

    const headers = { Signature: signature }

    const req = await fetch(Endpoints.SisuAuthorize, { method: 'post', headers, body })
    const ret = await req.json()
    if (!req.ok) this.checkTokenError(parseInt(req.headers.get('x-err')), ret)

    debug('Sisu Auth Response', ret)
    const xsts = {
      userXUID: ret.AuthorizationToken.DisplayClaims.xui[0].xid || null,
      userHash: ret.AuthorizationToken.DisplayClaims.xui[0].uhs,
      XSTSToken: ret.AuthorizationToken.Token,
      expiresOn: ret.AuthorizationToken.NotAfter
    }

    //await this.setCachedToken({ userToken: ret.UserToken, titleToken: ret.TitleToken, [createHash('rp://api.minecraftservices.com/')]: xsts })

    debug('[xbl] xsts', xsts)
    return xsts
  }

  async getXSTSToken (tokens, options = {}) {
    debug('[xbl] obtaining xsts token', { userToken: tokens.userToken, deviceToken: tokens.deviceToken, titleToken: tokens.titleToken })

    const payload = {
      RelyingParty: options.relyingParty,
      TokenType: 'JWT',
      Properties: {
        UserTokens: [tokens.userToken],
        DeviceToken: tokens.deviceToken,
        TitleToken: tokens.titleToken,
        OptionalDisplayClaims: options.optionalDisplayClaims,
        ProofKey: this.jwk,
        SandboxId: 'RETAIL'
      }
    }

    const body = JSON.stringify(payload)
    const signature = this.sign(Endpoints.XstsAuthorize, '', body).toString('base64')

    const headers = { ...this.headers, Signature: signature }

    const req = await fetch(Endpoints.XstsAuthorize, { method: 'post', headers, body })
    const ret = await req.json()
    if (!req.ok) this.checkTokenError(ret.XErr, ret)

    const xsts = {
      userXUID: ret.DisplayClaims.xui[0].xid || null,
      userHash: ret.DisplayClaims.xui[0].uhs,
      XSTSToken: ret.Token,
      expiresOn: ret.NotAfter
    }

    await this.setCachedToken({ [createHash(options.relyingParty)]: xsts })

    debug('[xbl] xsts', xsts)
    return xsts
  }

  /**
   * Requests an Xbox Live-related device token that uniquely links the XToken (aka xsts token)
   * @param {{ DeviceType, Version }} asDevice The hardware type and version to auth as, for example Android or Nintendo
   */
  async getDeviceToken () {
    const payload = {
      Properties: {
        AuthMethod: 'ProofOfPossession',
        Id: `{${nextUUID()}}`,
        DeviceType: 'Win32',
        SerialNumber: `{${nextUUID()}}`,
        Version: '0.0.0',
        ProofKey: this.jwk
      },
      RelyingParty: 'http://auth.xboxlive.com',
      TokenType: 'JWT'
    }

    const body = JSON.stringify(payload)
    const signature = this.sign(Endpoints.XboxDeviceAuth, '', body).toString('base64')
    const headers = { ...this.headers, Signature: signature }

    const ret = await fetch(Endpoints.XboxDeviceAuth, { method: 'post', headers, body }).then(checkStatus)

    //await this.setCachedToken({ deviceToken: ret })

    debug('Xbox Device Token', ret)
    return ret.Token
  }

  // This *only* works with live.com auth
  async getTitleToken (msaAccessToken, deviceToken) {
    const payload = {
      Properties: {
        AuthMethod: 'RPS',
        DeviceToken: deviceToken,
        RpsTicket: 't=' + msaAccessToken,
        SiteName: 'user.auth.xboxlive.com',
        ProofKey: this.jwk
      },
      RelyingParty: 'http://auth.xboxlive.com',
      TokenType: 'JWT'
    }
    const body = JSON.stringify(payload)
    const signature = this.sign(Endpoints.XboxTitleAuth, '', body).toString('base64')

    const headers = { ...this.headers, Signature: signature }

    const ret = await fetch(Endpoints.XboxTitleAuth, { method: 'post', headers, body }).then(checkStatus)

    await this.setCachedToken({ titleToken: ret })

    debug('Xbox Title Token', ret)
    return ret.Token
  }
}

module.exports = XboxTokenManager
