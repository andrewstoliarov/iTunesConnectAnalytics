'use strict';

const _ = require('underscore');
const request = require('request-promise');
const async = require('async');
const url = require('url');
const query = require('./query.js');

var Itunes = function(options){
  this.options = {
    baseURL: 'https://appstoreconnect.apple.com/olympus/v1',
    loginURL: 'https://idmsa.apple.com/appleauth/auth',
    settingsURL: 'https://appstoreconnect.apple.com/analytics/api/v1',
    checkUrl: 'https://appstoreconnect.apple.com/olympus/v1/session',
    appleWidgetKey: 'e0b80c3bf78523bfe80974d320935bfa30add02e1bff88ec2166c6bd5a706c42',
    concurrentRequests: 2,
    cookies: {},
    twoFAHandler: function(successCallback) {console.log('2FA handler');},
    errorExternalCookies: async function () {console.log('External headers error');},
    successAuthCookies: async function (headers) {}
  };

  _.extend(this.options, options);

  // Private
  this._cookies = this.options.cookies;
  this._queue = async.queue(
    this.executeRequest.bind(this),
    this.options.concurrentRequests
  );
  this._queue.pause();
};

Itunes.prototype.executeRequest = function(task, callback) {
  const query = task.query;
  const completed = task.completed;

  const requestBody = query.assembleBody();
  const uri = url.parse(query.apiURL + query.endpoint);

  if(requestBody.csv) {
    var isCSVRequest = true
    delete requestBody.csv
    var params = new URLSearchParams({data: JSON.stringify(requestBody)}).toString()
  }

  const config = {
    uri: uri,
    headers: this.getHeaders(),
    timeout: 300000, //5 minutes
    json: requestBody,
    resolveWithFullResponse: true
  };

  if(isCSVRequest) {
    delete config.json
    config['form'] = params
  }

  request.post(config).then(response => {
    completed(null, response.body)
    callback();
  }).catch(error => {
    completed(error, null);
    callback();
  });
}

Itunes.prototype.check = async function(username, password) {
  try {
    const config = {
      url: `${this.options.loginURL}/signin`,
      headers: {
        'Content-Type': 'application/json',
        'X-Apple-Widget-Key': this.options.appleWidgetKey,
        'Cookie': this.getCookies(),
      },
      json: {'accountName': username, 'password': password, 'rememberMe': true},
      resolveWithFullResponse: true
    };
    const responseCheck = await request.post(config);
    const cookies = responseCheck.headers['set-cookie'];
    if (!(cookies && cookies.length)) {
      throw new Error('There was a problem with loading the login page cookies.');
    }

    const myacinfo = /myacinfo=.+?;/.exec(cookies); //extract the itCtx cookie
    if (myacinfo == null || myacinfo.length == 0) {
      throw new Error('No myacinfo cookie :( Apple probably changed the login process');
    }

    this._cookies.myacinfo = myacinfo[0];
    return Promise.resolve(true);
  } catch (e) {
    console.log(e);
    await this.options.errorExternalCookies();
    return Promise.resolve(false);
  }
}

Itunes.prototype.login = async function(username, password) {
  if (await this.check(username, password)) {
    this._queue.resume();
    await this.options.successAuthCookies(this._cookies);
    return Promise.resolve();
  }

  return new Promise((resolve, reject) => {
    request.post({
      url: `${this.options.loginURL}/signin`,
      headers: {
        'Content-Type': 'application/json',
        'X-Apple-Widget-Key': this.options.appleWidgetKey,
        'Cookie': this.getCookies(),
      },
      json: {'accountName': username, 'password': password, 'rememberMe': true},
      resolveWithFullResponse: true
    }).catch((res) => {
      console.log(res)
      if (res.statusCode === 412) {
        const cookies = res.response.headers['set-cookie'];
        const headers = {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          scnt: res.response.headers['scnt'],
          'X-Apple-ID-Session-Id': res.response.headers['x-apple-id-session-id'],
          'X-Apple-Widget-Key': this.options.appleWidgetKey,
          'X-Requested-With': 'XMLHttpRequest',
          'X-Apple-Domain-Id': '3',
          Cookie: cookies
              .map((cookie) => cookie.split(';')[0])
              .join('; '),
        };
        return request.post({
          url: `https://idmsa.apple.com/appleauth/auth/repair/complete`,
          headers: headers,
          resolveWithFullResponse: true,
        });
      }

      if (res.statusCode !== 409) {
        return Promise.reject(res);
      }

      const headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'scnt': res.response.headers['scnt'],
        'X-Apple-ID-Session-Id': res.response.headers['x-apple-id-session-id'],
        'X-Apple-Widget-Key': this.options.appleWidgetKey,
        'X-Requested-With': 'XMLHttpRequest',
        'X-Apple-Domain-Id': '3',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors'
      };

      const body = res.response.body;
      if (body && body.authType === 'hsa2') {
        return this.HSA2Handler(res, headers);
      }

      //We need to get the 2fa code
      return this.TwoFAHandler(res, headers);

    }).then((response) => {
      console.log(response.headers)
      const cookies = response.headers['set-cookie'];
      if (!(cookies && cookies.length)) {
        throw new Error('There was a problem with loading the login page cookies. Check login credentials.');
      }
      const myAccount = /myacinfo=.+?;/.exec(cookies); //extract the account info cookie
      const des = /(DES.+?)=(.+?;)/.exec(cookies);
      if (myAccount == null || myAccount.length == 0 || des == null || des.length == 0) {
        throw new Error('No account cookie :( Apple probably changed the login process');
      }

      this._cookies.myacinfo = myAccount[0];
      this._cookies[des[1]] = des[0];

      return request.get({
        url: `${this.options.baseURL}/session`,
        followRedirect: false,
        headers: this.getHeaders(),
        resolveWithFullResponse: true
      });
    }).then(async (response) => {
      this.loginComplete(response);
      await this.options.successAuthCookies(this._cookies)
      resolve();
    }).catch((err) => {
      reject(err)
    });
  })
};

Itunes.prototype.TwoFAHandler = function(res, headers) {
  return new Promise((resolve, reject) => {
    this.options.twoFAHandler((code) => {
      resolve(code);
    });
  }).then((code) => {
    return request.post({
      url: `${this.options.loginURL}/verify/trusteddevice/securitycode`,
      headers: headers,
      json: {securityCode: {code: code}},
      resolveWithFullResponse: true
    }).then((res) => {
      return request.get({
        url: `${this.options.loginURL}/2sv/trust`,
        headers: headers,
        resolveWithFullResponse: true
      });
    }).catch((res) => {
      return Promise.reject(res);
    });
  });
}

Itunes.prototype.HSA2Handler = function(res, headers) {
  return new Promise((resolve, reject) => {
        return request.get({
          url: this.options.loginURL,
          headers: headers,
          resolveWithFullResponse: true
        }).then((res) => {
          this.options.twoFAHandler((code) => {
            resolve(code);
          });
        })
  }).then((code) => {
    return request.post({
      url: `${this.options.loginURL}/verify/trusteddevice/securitycode`,
      headers: headers,
      json: {securityCode: {code: code}},
      resolveWithFullResponse: true
    }).then((res) => {
      return request.get({
        url: `${this.options.loginURL}/2sv/trust`,
        headers: headers,
        resolveWithFullResponse: true
      });
    }).catch((res) => {
      return Promise.reject(res);
    });
  });
}

Itunes.prototype.loginComplete = function(response) {
  const cookies = response.headers['set-cookie'];
  if (!(cookies && cookies.length)) {
    throw new Error('There was a problem with loading the login page cookies.');
  }

  const itCtx = /itctx=.+?;/.exec(cookies); //extract the itCtx cookie
  if (itCtx == null || itCtx.length == 0) {
    throw new Error('No itCtx cookie :( Apple probably changed the login process');
  }

  this._cookies.itctx = itCtx[0];
  this._queue.resume();
}

Itunes.prototype.changeProvider = function(providerId) {
  return new Promise(((resolve, reject) => {
    request.post({
      url: `${this.options.baseURL}/session`,
      headers: this.getHeaders(),
      json: {provider: {providerId: providerId}},
      resolveWithFullResponse: true
    }).then((res) => {
      const cookies = res.headers['set-cookie'];
      const itCtx = /itctx=.+?;/.exec(cookies);
      if (itCtx == null || itCtx.length == 0) {
        reject(new Error('No itCtx cookie :( Apple probably changed the login process'));
      }

      this._cookies.itctx = itCtx[0];
      resolve()
    }).catch((err) => {
      reject(err);
    })
  }));
};

Itunes.prototype.getApps = function(callback) {
  const url = `${this.options.settingsURL}/app-info/all`;
  this.getAPIURL(url, callback);
};

Itunes.prototype.getSettings = function(callback) {
  const url = `${this.options.settingsURL}/settings/all`;
  this.getAPIURL(url, callback);
};

Itunes.prototype.request = function(query, callback) {
  this._queue.push({
    query: query,
    completed: callback
  });
};

Itunes.prototype.getAPIURL = function(uri, callback) {
  async.whilst((callback) => {
    callback(null, this._queue.paused);
  }, (callback) => {
    setTimeout(() => callback(null), 500);
  }, (err) => {
    request.get({
      uri: uri,
      headers: this.getHeaders()
    }).then((res) => {
      const data = JSON.parse(res);
      callback(null, data);
    }).catch((err) => {
      callback(err, null);
    });
  });
}

Itunes.prototype.getCookies = function() {
  return Object.keys(this._cookies).reduce((cookies, cookieName) => {
    return cookies + `${this._cookies[cookieName]} `
  }, '').trim()
};

Itunes.prototype.getHeaders = function() {
  return {
    'Content-Type': 'application/json;charset=UTF-8',
    'Accept': 'application/json, text/plain, */*',
    'Origin': 'https://analytics.itunes.apple.com',
    'X-Requested-By': 'analytics.itunes.apple.com',
    'Referer': 'https://analytics.itunes.apple.com/',
    'Cookie': this.getCookies()
  };
}

module.exports.Itunes = Itunes;
module.exports.AnalyticsQuery = query.AnalyticsQuery;
module.exports.frequency = query.frequency;
module.exports.measures = query.measures;
module.exports.dimension = query.dimension;
module.exports.dimensionFilterKey = query.dimensionFilterKey;
module.exports.region = query.region;
module.exports.territory = query.territory;
module.exports.platform = query.platform;
module.exports.source = query.source;
module.exports.frequency = query.frequency;
module.exports.queryType = query.queryType;
