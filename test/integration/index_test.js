'use strict';

/**
 * Module dependencies.
 */

var FastifyOAuthServer = require('../../oauthServer');
var InvalidArgumentError = require('oauth2-server/lib/errors/invalid-argument-error');
var NodeOAuthServer = require('oauth2-server');
var request = require('supertest');
var should = require('should');
var sinon = require('sinon');
const fastify = require('fastify');

/**
 * Test `FastifyOAuthServer`.
 */

describe('FastifyOAuthServer', function() {
    var app = null;

    var listen = function(){
      app.listen();
      return app.server;
    }

    beforeEach(function() {
        app = fastify();
        app.register(require('fastify-formbody'))
        app.register(require('../../'), {prefix: '/oauth', model: {}});
    });

    describe('authenticate()', function() {
        it('should return an error if `model` is empty', function(done) {
            app = fastify();

            app.register(require('fastify-formbody'))

            app.register(require('../../'), {prefix: '/oauth', model: {}});

            app.get('/test', (req, res) => {
                req.oauth(req, res);
            });

            request(listen())
                .get('/test')
                .expect(500)
                .expect({ error: 'invalid_argument', error_description: 'Invalid argument: model does not implement `getAccessToken()`' })
                .end(done);
        });

        it('should authenticate the request', function(done) {
            app = fastify();

            app.register(require('fastify-formbody'))

            var tokenExpires = new Date();
            tokenExpires.setDate(tokenExpires.getDate() + 1);

            var token = { user: {}, accessTokenExpiresAt: tokenExpires };
            var model = {
                getAccessToken: function() {
                    return token;
                }
            };

            app.register(require('../../'), {prefix: '/oauth', model: model});

            app.get('/test', (req, res) => {
                req.oauth(req, res);
            });

            request(listen())
                .get('/test')
                .set('Authorization', 'Bearer foobar')
                .expect(200)
                .end(done);
        });

        it('should authenticate the request with middleware', function(done) {
            app = fastify();

            app.register(require('fastify-formbody'))

            var tokenExpires = new Date();
            tokenExpires.setDate(tokenExpires.getDate() + 1);

            var token = { user: {}, accessTokenExpiresAt: tokenExpires };
            var model = {
                getAccessToken: function() {
                    return token;
                }
            };

            app.register(require('../../'), {prefix: '/oauth', model: model});

            app.get('/test', (req, res) => {
                req.oauth(req, res, function () {
                    res.send('test');
                });
            });

            request(listen())
                .get('/test')
                .set('Authorization', 'Bearer foobar')
                .expect(200)
                .end(done);
        });

        it('should unauthorized the request with middleware', function(done) {
            app = fastify();

            app.register(require('fastify-formbody'))

            var tokenExpires = new Date();
            tokenExpires.setDate(tokenExpires.getDate() - 60000);

            var token = { user: {}, accessTokenExpiresAt: tokenExpires };
            var model = {
                getAccessToken: function() {
                    return token;
                }
            };

            app.register(require('../../'), {prefix: '/oauth', model: model});

            app.get('/test', (req, res) => {
                req.oauth(req, res);
            });

            request(listen())
                .get('/test')
                .set('Authorization', 'Bearer foobar')
                .expect(401)
                .end(done);
        });

        it('should unauthorized the request with middleware custom response', function(done) {
            app = fastify();

            app.register(require('fastify-formbody'))

            var tokenExpires = new Date();
            tokenExpires.setDate(tokenExpires.getDate() + 60000);

            var token = { user: {}, accessTokenExpiresAt: tokenExpires };
            var model = {
                getAccessToken: function() {
                    return token;
                }
            };

            app.register(require('../../'), {prefix: '/oauth', model: model});

            app.get('/test', (req, res) => {
                req.oauth(req, res, (err, authenticated) => {
                    res.code(200).send('test');
                });
            });

            request(listen())
                .get('/test')
                .set('Authorization', 'Bearer foobar')
                .expect(200)
                .expect('test')
                .end(done);
        });
    });

    describe('authorize()', function() {
        it('should return an error', function(done) {
            app = fastify();

            app.register(require('fastify-formbody'));

            var model = {
                getAccessToken: function() {
                    return { user: {}, accessTokenExpiresAt: new Date() };
                },
                getClient: function() {
                    return { grants: ['authorization_code'], redirectUris: ['http://example.com'] };
                },
                saveAuthorizationCode: function() {
                    return {};
                }
            };

            app.register(require('../../'), {prefix: '/oauth', model: model});

            request(listen())
                .post('/oauth/authorize?state=foobiz')
                .set('Authorization', 'Bearer foobar')
                .send({ client_id: 12345 })
                .expect(400, function(err, res) {
                    console.log(res.body);
                    res.body.error.should.eql('invalid_request');
                    res.body.error_description.should.eql('Missing parameter: `response_type`');
                    done(err);
                });
        });

        it('should return a `location` header with the code', function(done) {
            app = fastify();

            app.register(require('fastify-formbody'))

            var model = {
                getAccessToken: function() {
                    return { user: {}, accessTokenExpiresAt: new Date().setDate(new Date().getTime() + 60 * 60 * 1000) };
                },
                getClient: function() {
                    return { grants: ['authorization_code'], redirectUris: ['http://example.com'] };
                },
                saveAuthorizationCode: function() {
                    return { authorizationCode: 123 };
                }
            };

            app.register(require('../../'), {prefix: '/oauth', model: model});

            request(listen())
                .post('/oauth/authorize?state=foobiz')
                .set('Authorization', 'Bearer foobar')
                .send({ client_id: 12345, response_type: 'code' })
                .expect('Location', 'http://example.com/?code=123&state=foobiz')
                .end(done);
        });

        it('should return an error if `model` is empty', function(done) {
            app = fastify();

            app.register(require('fastify-formbody'))

            app.register(require('../../'), {prefix: '/oauth', model: {}});

            request(listen())
                .post('/oauth/authorize')
                .expect({ error: 'invalid_argument', error_description: 'Invalid argument: model does not implement `getClient()`' })
                .end(done);
        });
    });

    describe('token()', function() {
        it('should return an `access_token`', function(done) {
            app = fastify();

            app.register(require('fastify-formbody'))

            var model = {
                getClient: function() {
                    return { grants: ['password'] };
                },
                getUser: function() {
                    return {};
                },
                saveToken: function() {
                    return { accessToken: 'foobar', client: {}, user: {} };
                }
            };

            app.register(require('../../'), {prefix: '/oauth', model: model});

            request(listen())
                .post('/oauth/token')
                .send('client_id=foo&client_secret=bar&grant_type=password&username=qux&password=biz')
                .expect({ access_token: 'foobar', token_type: 'bearer' })
                .end(done);
        });

        it('should return a `refresh_token`', function(done) {
            var model = {
                getClient: function() {
                    return { grants: ['password'] };
                },
                getUser: function() {
                    return {};
                },
                saveToken: function() {
                    return { accessToken: 'foobar', client: {}, refreshToken: 'foobiz', user: {} };
                }
            };
            var oauth = new FastifyOAuthServer({ model: model });

            app.use(oauth.token());

            request(listen())
                .post('/')
                .send('client_id=foo&client_secret=bar&grant_type=password&username=qux&password=biz')
                .expect({ access_token: 'foobar', refresh_token: 'foobiz', token_type: 'bearer' })
                .end(done);
        });

        it('should return an error if `model` is empty', function(done) {
            var oauth = new FastifyOAuthServer({ model: {} });

            app.use(oauth.token());

            request(listen())
                .post('/')
                .expect({ error: 'invalid_argument', error_description: 'Invalid argument: model does not implement `getClient()`' })
                .end(done);
        });
    });
});