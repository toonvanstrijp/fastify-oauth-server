'use strict';

/**
 * Module dependencies.
 */

var InvalidArgumentError = require('oauth2-server/lib/errors/invalid-argument-error');
var NodeOAuthServer = require('oauth2-server');
var Promise = require('bluebird');
var url = require('url');
var querystring = require('querystring');
var Request = require('oauth2-server').Request;
var Response = require('oauth2-server').Response;
var UnauthorizedRequestError = require('oauth2-server/lib/errors/unauthorized-request-error');

/**
 * Constructor.
 */

function FasitfyOAuthServer(options) {
    options = options || {};

    if (!options.model) {
        throw new InvalidArgumentError('Missing parameter: `model`');
    }

    this.useErrorHandler = options.useErrorHandler ? true : false;
    delete options.useErrorHandler;

    this.continueMiddleware = options.continueMiddleware ? true : false;
    delete options.continueMiddleware;

    this.server = new NodeOAuthServer(options);
}

/**
 * Authentication Middleware.
 *
 * Returns a middleware that will validate a token.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-7)
 */

FasitfyOAuthServer.prototype.authenticate = function(options) {
    var that = this;

    return function(req, res, next) {
        req.query = url.parse(req.url, true).query;
        var request = new Request(req);
        var response = new Response(res);
        return Promise.bind(that)
            .then(function() {
                return this.server.authenticate(request, response, options);
            })
            .tap(function() {
                if(options && options.hasOwnProperty('skipResponse') && options.skipResponse){
                    next(null, true);
                }else if(this.continueMiddleware){
                    next();
                }
            })
            .then(function() {
                if(options && !options.hasOwnProperty('skipResponse') && !options.skipResponse){
                    return handleResponse.call(this, req, res, response);
                }
            })
            .catch(function(e) {
                console.log(e);
                if(options && options.hasOwnProperty('skipResponse') && options.skipResponse){
                    next(e, false);
                }else{
                    return handleError.call(this, e, req, res, null, next);
                }
            });
    };
};

/**
 * Authorization Middleware.
 *
 * Returns a middleware that will authorize a client to request tokens.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-3.1)
 */

FasitfyOAuthServer.prototype.authorize = function(options) {
    var that = this;

    return function(req, res, next) {
        req.query = url.parse(req.url, true).query;
        var request = new Request(req);
        var response = new Response(res);

        let body = [];
        req.on('error', (err) => {
            console.error(err);
        }).on('data', (chunk) => {
            body.push(chunk);
        }).on('end', () => {
            body = Buffer.concat(body).toString();
        });

        return Promise.bind(that)
            .then(function() {
                try{
                    request.body = Object.assign(JSON.parse(body), request.body);
                }catch (e) {
                    request.body = Object.assign(querystring.parse(body), request.body);
                }
                return this.server.authorize(request, response, options);
            })
            .tap(function(code) {
                if(options && options.hasOwnProperty('skipResponse') && options.skipResponse){
                    next(null, code);
                }else if(this.continueMiddleware){
                    next();
                }
            })
            .then(function() {
                if(options && !options.hasOwnProperty('skipResponse') && !options.skipResponse){
                    return handleResponse.call(this, req, res, response);
                }
            })
            .catch(function(e) {
                if(options && options.hasOwnProperty('skipResponse') && options.skipResponse){
                    next(e, false);
                }else{
                    return handleError.call(this, e, req, res, null, next);
                }
            });
    };
};

/**
 * Grant Middleware.
 *
 * Returns middleware that will grant tokens to valid requests.
 *
 * (See: https://tools.ietf.org/html/rfc6749#section-3.2)
 */

FasitfyOAuthServer.prototype.token = function(options) {
    var that = this;

    return function(req, res, next) {
        req.query = url.parse(req.url, true).query;
        var request = new Request(req);
        var response = new Response(res);

        let body = [];
        req.on('error', (err) => {
            console.error(err);
        }).on('data', (chunk) => {
            body.push(chunk);
        }).on('end', () => {
            body = Buffer.concat(body).toString();
        });

        return Promise.bind(that)
            .then(function() {
                try{
                    request.body = Object.assign(JSON.parse(body), request.body);
                }catch (e) {
                    request.body = Object.assign(querystring.parse(body), request.body);
                }
                return this.server.token(request, response, options);
            })
            .tap(function(token) {
                if(options && options.hasOwnProperty('skipResponse') && options.skipResponse){
                    next(null, token);
                }else if(this.continueMiddleware){
                    next();
                }
            })
            .then(function() {
                if(options && !options.hasOwnProperty('skipResponse') && !options.skipResponse){
                    return handleResponse.call(this, req, res, response);
                }
            })
            .catch(function(e) {
                if(options && options.hasOwnProperty('skipResponse') && options.skipResponse){
                    next(e, false);
                }else{
                    return handleError.call(this, e, req, res, null, next);
                }
            });
    };
};

/**
 * Handle response.
 */
var handleResponse = function(req, res, response) {

    if (response.status === 302) {
        var location = response.headers.location;
        delete response.headers.location;
        for (let header in response.headers){
            res.setHeader(header, response.headers[header]);
        }
        res.setHeader('Location', location);
        res.statusCode = 302;
        res.end();
    } else {
        for (let header in response.headers){
            res.setHeader(header, response.headers[header]);
        }
        res.statusCode = response.status;
        res.setHeader('Content-Type', 'application/json');
        res.write(JSON.stringify(response.body));
        res.end();
    }
};

/**
 * Handle error.
 */

var handleError = function(e, req, res, response, next) {
    console.log(e);
    if (this.useErrorHandler === true) {
        next(e);
    } else {
        if (response) {
            for (let header in response.headers){
                res.setHeader(header, response.headers[header]);
            }
        }

        res.statusCode = e.code;
        res.setHeader('Content-Type', 'application/json');

        if (e instanceof UnauthorizedRequestError) {
            return res.end();
        }

        res.write(JSON.stringify({ error: e.name, error_description: e.message }));
        res.end();
    }
};

/**
 * Export constructor.
 */

module.exports = FasitfyOAuthServer;
