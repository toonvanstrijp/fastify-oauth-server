# Fastify OAuth Server [![Build Status](https://travis-ci.org/ToonvanStrijp/fastify-oauth-server.svg?branch=master)](https://travis-ci.org/ToonvanStrijp/fastify-oauth-server)

Complete, compliant and well tested module for implementing an OAuth2 Server/Provider with [fastify](https://github.com/fastify/fastify) in [node.js](http://nodejs.org/).

This is the fastify wrapper for [oauth2-server](https://github.com/thomseddon/node-oauth2-server).

## Installation

    $ npm install fastify-oauth-server

## Quick Start

The module provides one decorator - `oauth`.

`prefix` (default `/oauth`) is used within the plugin to create a prefix for the required routes:

`POST - /oauth/authorize`

`POST - /oauth/token`

Use the decorator to get the authentication state.

```js
// ./model.js

const argon2 = require('argon2');

const connect = require('../db');

module.exports.getAccessToken = async (accessToken) => {
  const db = await connect();
  const token = await db.oauth_tokens.findOne({ accessToken });

  let result;

  if (token) {
    result = {
      accessToken: token.accessToken,
      accessTokenExpiresAt: token.accessTokenExpiresAt,
      client: {
        id: token.clientId,
      },
      expires: token.accessTokenExpiresAt,
      user: {
        id: token.userId,
      },
    };
  }

  return result;
};

module.exports.getUserFromClient = async (client) => {
  const db = await connect();
  const oauthClient = await db.oauth_clients.findOne({
    id: client.clientId,
    userId: client.userId,
  });

  let result;
  if (oauthClient) {
    result = await db.users.findOne({ id: oauthClient.userId });
  }

  return result;
};

module.exports.getClient = async (clientId, clientSecret) => {
  const db = await connect();
  const query = {
    clientId,
  };
  if (clientSecret) {
    query.clientSecret = clientSecret;
  }

  const client = await db.oauth_clients.findOne(query);

  let result;
  if (client) {
    result = {
      clientSecret: client.clientSecret,
      grants: client.grants,
      id: client.clientId,
      userId: client.userId,
    };
  }

  return result;
};

module.exports.getRefreshToken = async (refreshToken) => {
  const db = await connect();
  const token = await db.oauth_tokens.findOne({ refreshToken });

  return {
    refreshToken: token.refreshToken,
    client: {
      id: token.clientId,
    },
    user: {
      id: token.userId,
    },
  };
};

module.exports.getUser = async (email, password) => {
  const db = await connect();
  let result;
  const user = await db.users.findOne({ email });

  let isValid = false;
  if (user) {
    isValid = await argon2.verify(user.password, password);
    if (isValid) {
      result = Object.assign({}, user, { password: null });
    }
  }

  return result;
};

module.exports.saveToken = async (token, client, user) => {
  const db = await connect();
  const inserted = await db.oauth_tokens.insert({
    accessToken: token.accessToken,
    accessTokenExpiresAt: token.accessTokenExpiresAt,
    clientId: client.id,
    refreshToken: token.refreshToken,
    refreshTokenExpiresAt: token.refreshTokenExpiresAt,
    userId: user.id,
  });

  let result;

  if (inserted) {
    result = {
      accessToken: token.accessToken,
      accessTokenExpiresAt: token.accessTokenExpiresAt,
      client: {
        id: client.id,
      },
      refreshToken: token.refreshToken,
      refreshTokenExpiresAt: token.refreshTokenExpiresAt,
      user: {
        id: user.id,
      },
    };
  }

  return result;
};

module.exports.revokeToken = async (token) => {
  const db = await connect();
  const result = await db.oauth_tokens.destroy({
    refreshToken: token.refreshToken,
  });

  return result;
};

module.exports.saveAuthorizationCode = () => false;
```

```js
var fastify = require('fastify');
var oauthserver = require('fastify-oauth-server');

var app = fastify();

app.register(oauthserver, {
    accessTokenLifetime: 4 * 60 * 60, // access token liftime in seconds
    model: require('./model'), // oauth2-server model with implemented methods for desired grants
    requireClientAuthentication: { // you can disable clientSecret requirement for different types of grants
    refresh_token: false,  // disable clientSecret requirement for refresh_token grant
    password: false, // disable clientSecret requirement for password grant
    ... // and so on
    },
    skipResponse: true, // do not use fastify-oauth-server's handleResponse function
});

app.post('/oauth/token', async (req, reply) => {
    const token = await req.oauth.token(req, reply);
    reply.send(token);
});

app.get('/status', async (req, reply) => {
    try {
      const token = await req.oauth.authenticate(req, reply);
      console.log(token); // will contain w/e you return from model's getAccessToken method
      reply.code(200).send({ status: 'ok' });
    } catch (e) {
      reply.code(401).send({
        errors: {
          error: e.toString(),
        },
      });
    }
});

app.listen(3000);
```
