"use strict";

exports.checkAcl = function(req, session, container, callback) {

    if(session.masterKey)
        return callback(null, true);

    container.getService('MONGODB').then(function(service) {

        service.send('findOne', {collectionName : session.appid, query : {where : {_className : '_Acl', name : req.className}}}, function(err, doc) {

            if(err)
                return callback(err, false);

            if(!doc.data || !doc.data.ACL)
                return callback(null, true);

            var acls = doc.data.ACL;

            function checkAllow(acl) {

                session.acl = acl;

                if(acl.master) {

                    session.masterKey = 'master';
                    session.acl.isAllow = true;
                    return true;
                }

                if(req.method === 'GET' && acl.read) {

                    session.acl.isAllow = true;
                    return true;
                }


                if(req.method !== 'GET' && acl.write) {

                    session.acl.isAllow = true;
                    return true;
                }

                session.acl.isAllow = false;
                return false;
            }

            if(acls[session.userid] || acls[session.username] || acls['*']) {

                var acl = acls[session.userid] || acls[session.username] || acls['*'];

                if(checkAllow(acl))
                    return callback(null, true);
            }

            service.send('find', {collectionName : session.appid, query : {where : {_className : '_Roles'}}}, function (err, docs) {

                function checkRole(id) {

                    if(acls[id] && checkAllow(acls[id])) {

                        return true;
                    }

                    for(var i=0, cnt=docs.data.length; i<cnt; i++) {

                        var role = docs.data[i];

                        if(role.roles) {

                            for(var j= 0, cntRole=role.roles.length; j<cntRole; j++) {

                                if(role.roles[j] === id && checkRole(role.name))
                                    return true;
                            }
                        }

                        if(role.users) {

                            for(var j= 0, cntUser=role.users.length; j<cntUser; j++) {

                                if(role.users[j] === id && checkRole(role.name))
                                    return true;
                            }
                        }
                    }
                }

                if(!err && docs && docs.data)
                    checkRole(session.userid);

                if(session.acl)
                    return callback(null, session.acl.isAllow);

                return callback(null, true);
            });
        });
    }).fail(function(err) {

        return callback(err, false);
    });
};
