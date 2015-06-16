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

            if(doc.data.ACL[session.userid] || doc.data.ACL[session.username] || doc.data.ACL['*']) {

                var acl = doc.data.ACL[session.userid] || doc.data.ACL[session.username] || doc.data.ACL['*'];

                session.acl = acl;

                if(acl.master) {

                    session.masterKey = 'master';
                    session.acl.isAllow = true;
                    return callback(null, true);
                }

                if(req.method === 'GET' && acl.read) {

                    session.acl.isAllow = true;
                    return callback(null, true);
                }


                if(req.method !== 'GET' && acl.write) {

                    session.acl.isAllow = true;
                    return callback(null, true);
                }


                return callback(null, false);
            }

            return callback(null, true);
        });
    }).fail(function(err) {

        return callback(err, false);
    });
};
