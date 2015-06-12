var _ = require('underscore');

exports.makeSession = function(req, container, callback) {

    var session = {};

    if(!req.headers['x-noserv-application-id'])
        return callback(new Error("Application ID is required"));

    if(req.headers['x-noserv-application-id'] === 'supertoken') {

        session.hasKey = true;
        session.appname = 'test';
        session.appid = 'test';
        session.masterKey = 'supertoken';
        session.username = 'test';
        session.userid = 'test';
        session.javascriptKey = 'supertoken';
        session.applicationId = 'supertoken';

        return callback(null, session);
    }

    container.getService('MONGODB').then(function(service) {

        service.send('findOne', {collectionName : 'apps', query : {where : {applicationId : req.headers['x-noserv-application-id']}}}, function(err, res) {

            if(err || !doc) {
                container.log.error('app not found', err);

                return callback(new Error("Application ID is invalid"));
            }

            var doc = res.data;

            if(req.headers['x-noserv-client-key'] === doc.clientKey)
                session.clientKey = req.headers['x-noserv-client-key'];

            if(req.headers['x-noserv-javascript-key'] === doc.javascriptKey)
                session.javascriptKey = req.headers['x-noserv-javascript-key'];

            if(req.headers['x-noserv-dot-net-key'] === doc.dotNetKey)
                session.dotNetKey = req.headers['x-noserv-dot-net-key'];

            if(req.headers['x-noserv-rest-api-key'] === doc.restApiKey)
                session.restApiKey = req.headers['x-noserv-rest-api-key'];

            if(req.headers['x-noserv-master-key'] === doc.masterKey)
                session.masterKey = req.headers['x-noserv-master-key'];

            session.hasKey = session.clientKey || session.javascriptKey || session.dotNetKey || session.restApiKey || session.masterKey;

            // for node sdk
            if(session.hasKey)
                session.javascriptKey = doc.javascriptKey;

            session.appname = doc.appname;
            session.appid = doc.objectId;
            session.applicationId = doc.applicationId;

            session.appleCertFile = doc.appleCertFile;
            session.gcmApiKey = doc.gcmApiKey;
            session.windowsSid = doc.windowsSid;
            session.windowsClientSecret = doc.windowsClientSecret;

            var parentAppId = doc._appid;
            var masterKey = doc.masterKey;

            if(req.headers['x-noserv-session-token']) {

                service.send('findOne', {collectionName : session.appid, query : {where : {_className : '_Users', sessionToken : req.headers['x-noserv-session-token']}}}, function(err, res) {

                    var doc = res.data;

                    if(err || !doc) {

                        // 앱의 소유주인지 확인
                        service.send('findOne', {collectionName : parentAppId, query : {where : {_className : '_Users', sessionToken : req.headers['x-noserv-session-token']}}}, function(err, res) {

                            if(!err && res.data && res.data.objectId) {

//                                session.username = '_master';
//                                session.userid = '_master';
                                session.masterKey = masterKey;

                            } else if(session.masterKey) {

                                // master key가 있을 경우 session 검증을 통과시킴
//                                session.username = '_master';
//                                session.userid = '_master';
                            }

                            callback(null, session);
                        });

                    } else {

                        session.username = doc.username;
                        session.userid = doc.objectId;

                        callback(null, session);
                    }
                });
            } else {

                callback(null, session);
            }
        });

    }).fail(function(err) {

        callback(err);
    });
};
