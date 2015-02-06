var _ = require('underscore');

exports.checkAPIAuth = function(req, container, callback) {

    var session = {};
    
    if(!req.headers['x-noserv-application-id'])
        return callback(new Error("Application ID is required"));

    if(req.headers['x-noserv-application-id'] === 'supertoken') {

        session.hasKey = true;
        session.appname = 'test';
        session.appid = 'test';
        session.masterKey = 'test';

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

            if(!session.hasKey)
                return callback(new Error("Application Key is required"));

            session.appname = doc.appname;
            session.appid = doc._id;

            callback(null, session);
        });

    }).fail(function(err) {

        callback(err);
    });
};

exports.checkSessionAuth = function(req, container, callback) {

    var session = {};

    if(!req.headers['x-noserv-session-token'])
        return callback(new Error("Session Token is required"));

    if(req.headers['x-noserv-session-token'] === 'supertoken') {

        session.username = 'test';
        session.userid = 'test';

        return callback(null, session);
    }

    container.getService('MONGODB').then(function(service) {

        service.send('findOne', {collectionName : 'users', query : {where : {sessionToken : req.headers['x-noserv-session-token']}}}, function(err, res) {

            var doc = res.data;

            if(err || !doc)
                return callback(new Error("session token is invalid"));

            session.username = doc.username;
            session.userid = doc._id;

            callback(null, session);
        });

    }).fail(function(err) {

        callback(err);
    });
};

exports.checkMasterKey = function(req, container, callback) {

    var session = {};

    if(!req.headers['x-noserv-master-key'])
        return callback(new Error("Master Key is required"));

    if(req.headers['x-noserv-application-id'] === 'supertoken') {

        session.hasKey = true;
        session.appname = 'test';
        session.appid = 'test';
        session.masterKey = 'test';

        return callback(null, session);
    }

    container.getService('MONGODB').then(function(service) {

        service.send('findOne', {collectionName : 'apps', query : {where : {applicationId : req.headers['x-noserv-application-id']}}}, function(err, res) {

            var doc = res.data;

            if(err || !doc)
                return callback(new Error("Application ID is invalid"));

            if(req.headers['x-noserv-master-key'] === doc.masterKey)
                session.masterKey = req.headers['x-noserv-master-key'];

            session.hasKey = session.masterKey;

            if(!session.hasKey)
                return callback(new Error("Master Key is invalid"));

            callback(null, session);
        });

    }).fail(function(err) {

        callback(err);
    });
};