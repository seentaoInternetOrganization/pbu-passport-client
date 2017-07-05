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

/**
 * 校验sid
 * @param  {object} req    请求体
 * @param  {object} res    响应体
 * @param  {object} config 配置文件
 * @return {Promise}        Promise
 */
function checkSid(req, res, config) {
    return new Promise(function(resolve, reject) {
        request.post({
            url: urljoin(config.passportUrl, 'sid.check'),
            form: {
                userToken: req.cookies[md5('userToken')],
                userId: req.cookies[md5('userId')],
                userName: req.cookies[md5('userName')],
                userType: req.cookies[md5('userType')],
                sid: req.cookies.PBUSID
            }
        }, function(err, response, body) {
            if (err) {
                reject(err);
            }

            const ret = JSON.parse(body);
            resolve(ret);
        })
    });
}

module.exports.pbupassport = pbupassport;
function pbupassport(config) {
    return function(req, res, next) {
        if (req.method === 'GET' ) {
            if (!req.cookies.PBUSID) {
                if (!req.query.ticket) {
                    res.redirect(appendQuery(config.passportUrl, { redirectUrl:  urljoin(config.siteDomain, req.originalUrl) }));
                    return;
                }else {
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
            }else {
                //如果有userInfo等信息，则继续
                if (req.cookies[md5('userToken')]
                    && req.cookies[md5('userId')]
                    && req.cookies[md5('userName')]
                    && req.cookies[md5('userType')]) {

                    checkSid(req, res, config).then(function(ret) {
                        if (ret.same !== 'true') {
                            res.redirect(appendQuery(urljoin(config.passportUrl, 'login'), { redirectUrl:  urljoin(config.siteDomain, req.originalUrl) }));
                            return;
                        }else {
                            return next();
                        }
                    });
                }else {
                    res.redirect(appendQuery(urljoin(config.passportUrl, 'login'), { redirectUrl:  urljoin(config.siteDomain, req.originalUrl) }));
                    return;
                }
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
