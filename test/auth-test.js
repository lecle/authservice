var auth = require('../lib/auth');

var req = {
    data : {
        collectionName : 'testcol',
        query : {where : {test : 'data'}},
        data : {test : 'data'},
        keys : ['test']
    }
};

var res = function(done) {

    return {
        send : function() {done();},
        error : function(err) {done(err);}
    };
};

describe('auth', function() {
    describe('#init()', function () {
        it('should initialize without error', function (done) {

            // manager service load
            var dummyContainer = {
                addListener: function () {
                }
            };

            auth.init(dummyContainer, function (err) {

                auth.close(done);
            });
        });
    });

    describe('#check()', function () {
        it('should check without error', function (done) {

            // manager service load
            var dummyContainer = {
                addListener: function () {
                }
            };

            auth.init(dummyContainer, function (err) {

                auth.check(req, res(done));
                auth.close(function() {});
            });
        });
    });
});
