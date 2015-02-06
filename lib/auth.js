"use strict";

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

    res.send({code:200, message:'OK'});
}