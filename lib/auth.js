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

    req.data.session = {};

    async.waterfall([

        function(callback) {

            if(req.data.checklist.indexOf('APIAUTH') < 0)
                callback(null);

            authChecker.checkAPIAuth(req.data, exports.container, function(err, doc) {

                if(err)
                    return callback(err, 'error');

                _.defaults(req.data.session, doc);
                callback(null);
            });
        },
        function(callback) {

            if(req.data.checklist.indexOf('SESSION') < 0)
                callback(null);

            authChecker.checkAPIAuth(req.data, exports.container, function(err, doc) {

                if(err)
                    return callback(err, 'error');

                _.defaults(req.data.session, doc);
                callback(null);
            });
        },
        function(callback) {

            if(req.data.checklist.indexOf('MASTERKEY') < 0)
                callback(null);

            authChecker.checkAPIAuth(req.data, exports.container, function(err, doc) {

                if(err)
                    return callback(err, 'error');

                _.defaults(req.data.session, doc);
                callback(null);
            });
        }

    ], function (err, result) {

        if(err)
            return res.error(err);

        res.send({session:req.data.session});
    });
}