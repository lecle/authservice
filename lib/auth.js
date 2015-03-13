"use strict";

var authChecker = require('./authChecker');

exports.container = null;

exports.init = function(container, callback) {

    exports.container = container;

    container.addListener('check', onCheck);

    callback(null);
};

exports.close = function(callback) {

    callback(null);
};

exports.check = onCheck;

function onCheck(req, res) {

    var async = require('async');
    var _ = require('underscore');

    authChecker.makeSession(req.data, exports.container, function(err, doc) {

        if(err)
            return res.error(err);

        if(req.data.checklist.indexOf('APIAUTH') >= 0) {

            if(!doc.hasKey)
                return res.error(new Error('Application Key is required'));
        }

        if(req.data.checklist.indexOf('SESSION') >= 0) {

            if(!doc.userid)
                return res.error(new Error("session token is invalid"));
        }

        if(req.data.checklist.indexOf('MASTERKEY') >= 0) {

            if(!doc.masterKey)
                return res.error(new Error("Master Key is required"));
        }

        res.send({session:doc});
    });
}