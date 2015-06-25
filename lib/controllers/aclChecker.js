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

            service.send('find', {collectionName : session.appid, query : {where : {_className : '_Roles'}}}, function (err, docs) {

                var depRoles = ['*', session.userid, session.username];

                var acls = doc.data.ACL;

                if(!err && docs && docs.data) {

                    getDependentRoleList(docs.data, depRoles, session.userid);
                }

                return callback(null, checkAllows(acls, depRoles, session, req.method));
            });
        });
    }).fail(function(err) {

        return callback(err, false);
    });
};

function checkAllows(acls, roles, session, method) {

    for(var i= 0, cnt=roles.length; i<cnt; i++) {

        if(acls[roles[i]] && checkAllow(acls[roles[i]], session, method))
            break;
    }

    if(session.acl) {

        session.acl.dependentRoles = roles;

        return session.acl.isAllow;
    }

    return true;
}

function getDependentRoleList(roles, depRoles, id) {

    for(var i=0, cnt=roles.length; i<cnt; i++) {

        var role = roles[i];

        if(role.roles) {

            for(var j= 0, cntRole=role.roles.length; j<cntRole; j++) {

                if(role.roles[j] === id) {

                    depRoles.push(role.name);
                    getDependentRoleList(roles, depRoles, role.name);
                }
            }
        }

        if(role.users) {

            for(var j= 0, cntUser=role.users.length; j<cntUser; j++) {

                if(role.users[j] === id) {

                    depRoles.push(role.name);
                    getDependentRoleList(roles, depRoles, role.name);
                }
            }
        }
    }
}

function checkAllow(acl, session, method) {

    session.acl = acl;

    if(acl.master) {

        session.masterKey = 'master';
        session.acl.isAllow = true;
        return true;
    }

    if(method === 'GET' && acl.read) {

        session.acl.isAllow = true;
        return true;
    }

    if(method !== 'GET' && acl.write) {

        session.acl.isAllow = true;
        return true;
    }

    session.acl.isAllow = false;
    return false;
}
