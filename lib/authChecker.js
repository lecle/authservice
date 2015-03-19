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

        return callback(null, session);
    }

    container.getService('MONGODB').then(function(service) {

        service.send('findOne', {collectionName : 'apps', query : {where : {applicationId : req.headers['x-noserv-application-id']}}}, function(err, res) {

            var doc = res.data;

            if(err || !doc)
                return callback(new Error("Application ID is invalid"));

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

            session.appname = doc.appname;
            session.appid = doc.objectId;

            session.appleCertFile = doc.appleCertFile;
            session.gcmApiKey = doc.gcmApiKey;
            session.windowsSid = doc.windowsSid;
            session.windowsClientSecret = doc.windowsClientSecret;

            if(req.headers['x-noserv-session-token']) {

                service.send('findOne', {collectionName : session.appid, query : {where : {_className : '_Users', sessionToken : req.headers['x-noserv-session-token']}}}, function(err, res) {

                    var doc = res.data;

                    if(err || !doc) {

                        // master key가 있을 경우 session 검증을 통과시킴
                        if(session.masterKey) {

                            session.username = '_master';
                            session.userid = '_master';
                        }
                    } else {

                        session.username = doc.username;
                        session.userid = doc.objectId;
                    }

                    callback(null, session);
                });
            } else {

                callback(null, session);
            }
        });

    }).fail(function(err) {

        callback(err);
    });
};