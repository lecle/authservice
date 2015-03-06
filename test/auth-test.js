var auth = require('../lib/auth');

var req = {
    data : {

        checklist : ['APIAUTH', 'SESSION', 'MASTERKEY'],
        headers : {
            'x-noserv-session-token' : 'supertoken',
            'x-noserv-application-id' : 'supertoken',
            'x-noserv-master-key' : 'supertoken'
        },
        session : {
            appid : 'test',
            userid : 'test',
            masterKey : 'supertoken'
        }
    }
};

var res = function(done) {

    return {
        send : function() {done();},
        error : function(err) {done(err);}
    };
};

var dummyContainer = {
    addListener : function(){},
    getService : function(name) {

        return {
            then : function(callback){ callback({send : function(command, data, callback) {

                callback(null, {data : {objectId : 'test', masterKey : 'test'}});
            }});

                return {fail : function(){}};
            }
        };
    }
};

describe('auth', function() {
    describe('#init()', function () {
        it('should initialize without error', function (done) {

            auth.init(dummyContainer, function (err) {

                auth.close(done);
            });
        });
    });

    describe('#check()', function () {
        it('should check without error', function (done) {

            auth.init(dummyContainer, function (err) {

                auth.check(req, res(done));
                auth.close(function() {});
            });
        });

        it('should check another keys without error', function (done) {

            auth.init(dummyContainer, function (err) {

                req.data.headers = {
                    'x-noserv-session-token' : 'test',
                    'x-noserv-application-id' : 'test',
                    'x-noserv-master-key' : 'test'
                };

                auth.check(req, res(done));
                auth.close(function() {});
            });
        });
    });
});
