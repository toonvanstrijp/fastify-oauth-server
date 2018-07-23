const FastifyOAuthServer = require('./oauthServer');
const qs = require('qs');
const fp = require('fastify-plugin');

function plugin (fastify, options, next) {
    const opts = Object.assign({prefix: '/oauth'}, options || {});
    const oauthServer = new FastifyOAuthServer(opts);
    const prefix = opts.prefix === null || opts.prefix === undefined ? '' : opts.prefix;

    fastify.decorateRequest('oauth', oauth);

    if(!fastify.hasContentTypeParser('application/x-www-form-urlencoded')){
        fastify.addContentTypeParser(
            'application/x-www-form-urlencoded',
            {parseAs: 'buffer', bodyLimit: opts.bodyLimit},
            contentParser
        );
    }

    function oauth(request, reply, next){
        if(next === undefined){
            oauthServer.authenticate()(request.raw, reply.res, () => {
                reply.res.end();
            });
        }else{
            oauthServer.authenticate({skipResponse: true})(request.raw, reply.res, next);
        }
    }

    function contentParser (req, body, done) {
        done(null, qs.parse(body.toString()));
    }

    fastify.post(prefix+'/authorize', (req, reply) => {
        req.raw.query = req.query;
        req.raw.body = req.body;
        oauthServer.authorize()(req.raw, reply.res, () => {
            reply.res.end();
        });
    });

    fastify.post(prefix+'/token', (req, reply) => {
        req.raw.query = req.query;
        req.raw.body = req.body;

        oauthServer.token()(req.raw, reply.res, () => {
            reply.res.end();
        });
    });

    next();
}

module.exports = fp(plugin, {
    fastify: '>= 0.39.0',
    name: 'fastify-oauth-server'
});