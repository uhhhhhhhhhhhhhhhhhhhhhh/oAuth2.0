const debug = require('debug')('prismarine-auth')
const fetch = require('node-fetch')
const express = require('express')
const { Endpoints } = require('../common/Constants')
const { checkStatus } = require('../common/Util')

class LiveTokenManager {
  constructor (clientId, scopes, cache) {
    this.clientId = clientId
    this.scopes = scopes
    this.cache = cache
  }

  async verifyTokens () {
    if (this.forceRefresh) try { await this.refreshTokens() } catch { }
    const at = await this.getAccessToken()
    const rt = await this.getRefreshToken()
    if (!at || !rt) {
      return false
    }
    debug('[live] have at, rt', at, rt)
    if (at.valid && rt) {
      return true
    } else {
      try {
        await this.refreshTokens()
        return true
      } catch (e) {
        console.warn('Error refreshing token', e) 
        return false
      }
    }
  }

  async refreshTokens (rtoken) {

    console.log("REFRESHING TOKEN: " + rtoken)

    if (!rtoken) {
      const rtoken = await this.getRefreshToken()
    }

    const codeRequest = {
      method: 'post',
      body: new URLSearchParams({ scope: this.scopes, client_id: this.clientId, grant_type: 'refresh_token', refresh_token: rtoken }).toString(),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      credentials: 'include' 
    }

    const token = await fetch(Endpoints.LiveTokenRequest, codeRequest).then(checkStatus)
    return { accessToken: token.access_token, refreshToken: token.refresh_token }
  }

  async getAccessToken () {
    const { token } = await this.cache.getCached()
    if (!token) return
    const until = new Date(token.obtainedOn + token.expires_in) - Date.now()
    const valid = until > 1000
    return { valid, until, token: token.access_token }
  }

  async getRefreshToken () {
    const { token } = await this.cache.getCached()
    if (!token) return
    const until = new Date(token.obtainedOn + token.expires_in) - Date.now()
    const valid = until > 1000
    return { valid, until, token: token.refresh_token }
  }

  async updateCache (data) {
    await this.cache.setCachedPartial({
      token: {
        ...data,
        obtainedOn: Date.now()
      }
    })
  }

  async authDeviceCode (deviceCodeCallback, clickUrl) {
    const acquireTime = Date.now()
    const codeRequest = {
      method: 'post',
      body: new URLSearchParams({ scope: this.scopes, client_id: this.clientId, response_type: 'device_code' }).toString(),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      credentials: 'include' // This cookie handler does not work on node-fetch ...
    }

    const cookies = []

    const res = await fetch(Endpoints.LiveDeviceCodeRequest, codeRequest)
      .then(res => {
        if (res.status !== 200) {
          res.text().then(console.warn)
          throw Error('Failed to request live.com device code')
        }
        for (const cookie of Object.values(res.headers.raw()['set-cookie'])) {
          const [keyval] = cookie.split(';')
          cookies.push(keyval)
        }
        return res
      })
      .then(checkStatus).then(resp => {
        if (clickUrl)
          clickUrl.redirect("https://login.live.com/oauth20_remoteconnect.srf?lc=1033&otc=" + resp.user_code)
        console.log("https://login.live.com/oauth20_remoteconnect.srf?lc=1033&otc=" + resp.user_code)
        deviceCodeCallback(resp)
        return resp
      })
    const expireTime = acquireTime + (res.expires_in * 1000) - 100 /* for safety */

    this.polling = true
    while (this.polling && expireTime > Date.now()) {
      await new Promise(resolve => setTimeout(resolve, res.interval * 1000))
      try {
        const verifi = {
          method: 'post',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Cookie: cookies.join('; ')
          },
          body: new URLSearchParams({
            client_id: this.clientId,
            device_code: res.device_code,
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code'
          }).toString()
        }

        const token = await fetch(Endpoints.LiveTokenRequest + '?client_id=' + this.clientId, verifi)
          .then(res => res.json()).then(res => {
            if (res.error) {
              if (res.error === 'authorization_pending') {
                console.log(`[sign-in] Still waiting:`, res.error_description)
              }
            } else {
              return res
            }
          })
        if (!token) continue
        this.polling = false
        return { accessToken: token.access_token, refreshToken: token.refresh_token }
      } catch (e) {
        console.debug(e)
      }
    }
    this.polling = false
    console.log('Authentication failed, timed out')
  }
}

module.exports = LiveTokenManager
