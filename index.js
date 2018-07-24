const FastifyOAuthServer = require('./oauthServer');
const fp = require('fastify-plugin');

function plugin (fastify, options, next) {
    const opts = Object.assign({}, options || {});
    const oauthServer = new FastifyOAuthServer(opts);

    fastify.decorateRequest('oauth', {
        authenticate: authenticate,
        authorize: authorize,
        token: token,
    });

    function authenticate(req, reply){
        return new Promise((resolve, reject) => {
            oauthServer.authenticate({skipResponse: true})(req.raw, reply.res, function (err, authenticated) {
               if(err){
                   reject(err);
               }else{
                   resolve(authenticated);
               }
            });
        });
    }

    function authorize(req, reply){
        return new Promise((resolve, reject) => {
            req.raw.query = req.query;
            req.raw.body = req.body;
            oauthServer.authorize({skipResponse: true})(req.raw, reply.res, function (err, authenticated) {
                if(err){
                    reject(err);
                }else{
                    resolve(authenticated);
                }
            });
        });
    }

    function token(req, reply){
        return new Promise((resolve, reject) => {
            req.raw.query = req.query;
            req.raw.body = req.body;
            oauthServer.token({skipResponse: true})(req.raw, reply.res, function (err, authenticated) {
                if(err){
                    reject(err);
                }else{
                    resolve(authenticated);
                }
            });
        });
    }

    next();
}

module.exports = fp(plugin, {
    fastify: '>= 0.39.0',
    name: 'fastify-oauth-server'
});