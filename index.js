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
    'memberType',
    'schoolName',
    'schoolId',
    'schoolUrl',
    'PBU_AUTHR_SIG',
    'orgId',
    'orgType',
    'memberId'
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

    function handleGET(req, res, next) {
        //先响应退出
        if (req.path === '/logout') {
            //清cookie
            cookiesToClear.forEach((item) => {
                res.clearCookie(item);
            });

            res.json({
                code: 200
            });
            return;
        }

        if (req.query.ticket) {
            //只要有票，就重新创建sid等信息
            const maxAge = config.maxAge;
            //用ticket换sid
            getSidByTicket(req, res, config)
            .then(function(ret) {
                if (ret.code != 200) {
                    res.redirect(appendQuery(urljoin(config.passportUrl, 'login'), {
                        redirectUrl:  urljoin(config.siteDomain, req.originalUrl),
                        errMsg: JSON.stringify(ret)
                    }));
                    return;
                }

                res.cookie(PBUSID, ret.sid, { httpOnly: true });
                res.cookie(md5('userName'), base64Encode(ret.userName + ''), { });
                res.cookie(md5('userId'), base64Encode(ret.userId + ''), { });
                res.cookie(md5('userToken'), base64Encode(ret.userToken + ''), { });
                res.cookie(md5('userType'), base64Encode(ret.userType + ''), { });
                res.redirect(appendQuery(req.originalUrl, {
                    ticket: null
                }, {
                    removeNull: true
                }));
                return;
            });

            //hold
            return;
        }else if (req.cookies.PBUSID    //如果信息全面，则放行
            && req.cookies.PBUSID !== 'undefined'
            && req.cookies[md5('userToken')] && base64Decode(req.cookies[md5('userToken')]) !== 'undefined'
            && req.cookies[md5('userId')] && base64Decode(req.cookies[md5('userId')]) !== 'undefined'
            && req.cookies[md5('userName')]
            && req.cookies[md5('userType')]) {

            return next()
        }else {
            //重新去生成ticket
            res.redirect(appendQuery(config.passportUrl, { redirectUrl:  urljoin(config.siteDomain, req.originalUrl) }));
            return
        }

        return next()
    }

    function handlePOST(req, res, next) {
        if (req.path === '/logout'
            || req.path === '/login') {
            //登出操作
            cookiesToClear.forEach((item) => {
                res.clearCookie(item);
            });
            res.redirect(appendQuery(urljoin(config.passportUrl, req.path), {
                errMsg: req.query.errMsg ? req.query.errMsg : '',
                redirectUrl: config.siteDomain,
            }));
            return;
        }

        return next();
    }

    return function(req, res, next) {
        switch(req.method) {
            case 'GET':
                return handleGET(req, res, next)
                break

            case 'POST':
                return handlePOST(req, res, next)
                break
        }
    }
}
