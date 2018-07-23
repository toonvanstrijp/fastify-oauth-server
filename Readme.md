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
var fastify = require('fastify');
var oauthserver = require('fastify-oauth-server');

var app = fastify();


app.register(oauthserver, {
    prefix: '/oauth',
    model: {}, // See https://github.com/thomseddon/node-oauth2-server for specification
    grants: ['password'],
    debug: true
});

app.get(function(req, res){
    req.oauth(req, res, function(err, authenticated) {
      if(err){
          res.code(401).send('unauthenticated!');
      }else{
          res.code(200).send('authenticated!');
      }
    });
})

app.listen(3000);
```
