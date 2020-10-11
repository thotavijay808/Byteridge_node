﻿const config = require('config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');
const mongoose = require('mongoose');
const User = db.User;


module.exports = {
    authenticate,
    getAll,
    getById,
    create,
    update,
    delete: _delete,
    logout,
    auditGetAllUser
};

async function authenticate({ username, password },myIP) {
  
    const user = await User.findOne({ username });
    if(user){
       let user1 =  await User.update({'_id':user._id},{$set:{'loginTime':Date.now(),'IP':myIP}});
    }
    if (user && bcrypt.compareSync(password, user.hash)) {
        const { hash, ...userWithoutHash } = user.toObject();
        const token = jwt.sign({ sub: user.id }, config.secret);
        return {
            ...userWithoutHash,
            token
        };
    }
}

async function getAll() {
    return await User.find().select('-hash');
}

async function getById(id) {
    return await User.findById(id).select('-hash');
}

async function create(userParam) {
    // validate
    if (await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    const user = new User(userParam);
    // hash password
    if (userParam.password) {
        user.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // save user
    await user.save();
}

async function update(id, userParam) {
    const user = await User.findById(id);

    // validate
    if (!user) throw 'User not found';
    if (user.username !== userParam.username && await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    // hash password if it was entered
    if (userParam.password) {
        userParam.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // copy userParam properties to user
    Object.assign(user, userParam);

    await user.save();
}

async function _delete(id) {
    await User.findByIdAndRemove(id);
}

async function logout(user){
    if(user){
        let user1 =  await User.update({'_id':user._id},{$set:{'logoutTime':Date.now()}});
     }
}

async function auditGetAllUser(user){
   
}

async function auditGetAllUser(user) {
    const audit = await User.findById(user);
    if(audit.role != "auditor"){
        // throw new Error (audit.username+"  Access denied...");
        return 401;
    }
    else{
        return audit;
    }
}