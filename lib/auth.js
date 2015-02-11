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

    var tasks = [];

    var queue = async.queue(function(task, cb) {

        tasks.push(task);

        cb();
    }, 3);

    queue.drain = function() {

        var session = {};

        for(var i= 0, cnt=tasks.length; i<cnt; i++) {

            if(tasks[i].error) {

                return res.error(tasks[i].error);
            }

            if(tasks[i].session) {

                _.defaults(session, tasks[i].session);
            }
        }

        res.send({session:session});
    };

    function pushSession(err, session) {

        if(err)
            queue.push({error : err});
        else
            queue.push({session : session});
    }

    var checkCnt = 0;

    for(var i= 0, cnt=req.data.checklist.length; i<cnt; i++) {

        switch(req.data.checklist[i]) {

            case 'APIAUTH' :
                checkCnt++;
                authChecker.checkAPIAuth(req.data, exports.container, pushSession);
                break;

            case 'SESSION' :
                checkCnt++;
                authChecker.checkSessionAuth(req.data, exports.container, pushSession);
                break;

            case 'MASTERKEY' :
                checkCnt++;
                authChecker.checkMasterKey(req.data, exports.container, pushSession);
                break;

            default :
                queue.push({error : new Error('AuthChecker not found')});
        }
    }

    if(checkCnt === 0)
        res.error(new Error('AuthChecker not found'));
}