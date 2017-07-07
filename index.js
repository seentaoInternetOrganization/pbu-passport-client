/**
 * @author Chenzhyc
 * @description PBU Passport client
 */

const md5 = require('blueimp-md5');
const request = require('request');
const formurlencoded = require('form-urlencoded');
const appendQuery = require('append-query');
const validator = require('validator');
const urljoin = require('url-join');

if (process.env.NODE_ENV !== 'production') {
    request.debug = true;
}

/**
 * sessionId 名称
 * @type {String}
 */
const PBUSID = 'PBUSID';

/**
 * decode a base64 encoded string
 * @param  {[type]} encodedString [description]
 * @return {[type]}               [description]
 */
function base64Decode(encodedString) {
    if (typeof encodedString !== 'string') {
        return null;
    }

    return new Buffer(encodedString, 'base64').toString();
}

/**
 * encode a string base64
 * @param  {[type]} originalString [description]
 * @return {[type]}                [description]
 */
function base64Encode(originalString) {
    if (typeof originalString !== 'string') {
        return null;
    }

    return new Buffer(originalString + '').toString('base64');
}

//退出时需要清掉的cookies
const cookiesToClear = [
    md5('userId'),
    md5('userName'),
    md5('userType'),
    md5('userToken'),
    'PBUSID',
    md5('memberType'),
    md5('schoolName'),
    md5('schoolId'),
    md5('schoolUrl'),
    'PBU_AUTHR_SIG'
]

/**
 * 根据ticket换取local sid
 * @param  {object} req request
 * @param  {object} res response
 * @return {Promise}     Promise
 */
function getSidByTicket(req, res, config) {
    return new Promise(function(resolve, reject) {
        request.post({
            url: urljoin(config.ssoApiUrl, 'sid.local.get'),
            form: {
                ticket: req.query.ticket,
                url: urljoin(config.siteDomain, appendQuery(req.originalUrl, { ticket: null }, { removeNull: true }))
            }
        }, function(err, response, body) {

            if (err) {
                reject(err);
            }

            const ret = JSON.parse(body);
            resolve(ret);
        });
    });
}

module.exports.pbupassport = pbupassport;
function pbupassport(config) {
    return function(req, res, next) {
        if (req.method === 'GET' ) {
            if (!req.query.ticket) {
                if (!req.cookies.PBUSID) {
                    //没票且没sid，则重新登录
                    res.redirect(appendQuery(config.passportUrl, { redirectUrl:  urljoin(config.siteDomain, req.originalUrl) }));
                    return;
                }else {

                    if (req.cookies[md5('userToken')]
                        && req.cookies[md5('userId')]
                        && req.cookies[md5('userName')]
                        && req.cookies[md5('userType')]) {
                        //如果有sid且有userInfo等信息，则继续
                    }else {
                        //userInfo信息不全，需重新登录
                        res.redirect(appendQuery(urljoin(config.passportUrl, 'login'), { redirectUrl:  urljoin(config.siteDomain, req.originalUrl) }));
                        return;
                    }
                }
            }else {
                //只要有新票，就重新创建sid等信息
                const maxAge = config.maxAge;
                //用ticket换sid
                getSidByTicket(req, res, config).then(function(ret) {
                    res.cookie(PBUSID, ret.sid, { maxAge: maxAge, httpOnly: true });
                    res.cookie(md5('userName'), base64Encode(ret.userName), { maxAge: maxAge });
                    res.cookie(md5('userId'), base64Encode(ret.userName), { maxAge: maxAge });
                    res.cookie(md5('userToken'), base64Encode(ret.userName), { maxAge: maxAge });
                    res.cookie(md5('userType'), base64Encode(ret.userName), { maxAge: maxAge });
                    res.redirect(appendQuery(req.originalUrl, { ticket: null }, { removeNull: true }));
                    return;
                });

                return;
            }

            if (req.path === '/logout') {
                //清cookie
                cookiesToClear.forEach((item) => {
                    res.clearCookie(item);
                });

                return;
            }
        }else if (req.method === 'POST') {
            if (req.path === '/logout') {
                //登出操作
                cookiesToClear.forEach((item) => {
                    res.clearCookie(item);
                });
                res.redirect(appendQuery(urljoin(config.passportUrl, 'logout'), { redirectUrl: config.siteDomain }));
                return;
            }
        }

        return next();
    };
}

// pbupassport({
//     passportUrl: '',
//     siteDomain: '',
//     maxAge: '',
//     ssoApiUrl: ''
// })
