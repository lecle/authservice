"use strict";

var authChecker = require('./controllers/authChecker');
var aclChecker = require('./controllers/aclChecker');

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

    var _ = require('underscore');

    authChecker.makeSession(req.data, exports.container, function(err, doc) {

        if(err)
            return res.error(err);

        if(req.data.checklist.indexOf('APIAUTH') >= 0) {

            if(!doc.hasKey)
                return res.error(new Error('Application Key is required'));
        }

        if(req.data.checklist.indexOf('SESSION') >= 0) {

            if(!doc.userid && !doc.masterKey)
                return res.error(new Error("session token is invalid"));
        }

        if(req.data.checklist.indexOf('MASTERKEY') >= 0) {

            if(!doc.masterKey)
                return res.error(new Error("Master Key is required"));
        }

        if(!req.data.className)
            return res.send({session:doc});

        aclChecker.checkAcl(req.data, doc, exports.container, function(err, isAllow) {

            if(err)
                return res.error(err);

            if(!isAllow)
                return res.error(403, new Error('Unauthorized'));

            return res.send({session:doc});
        });
    });
}
