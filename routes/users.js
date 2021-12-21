// routes/users.js

var express = require('express');
var secured = require('../lib/middleware/secured');
var router = express.Router();
const ds = require('../datastore.js');
const datastore = ds.datastore;
const USER = "User";


function save_user(user_id){
    var q = datastore.createQuery(USER);
    return datastore.runQuery(q).then( (entities) => {
        users = entities[0];
        const user_exists = (user) => user.user_id === user_id;
        if (!users.some(user_exists)){
          var key = datastore.key(USER);
          const new_user = {"user_id": user_id};
          return datastore.save({"key":key, "data":new_user});
        }
    });
}


/* GET user profile. */
router.get('/user', secured(), function (req, res, next) {
    const { _raw, _json, ...data } = req.user; 
    const user = save_user(data.user_id);
    res.render('user', {
        id_token: data.id_token,
        user_id: data.user_id,
        title: 'Profile page'
    });
});

module.exports = router;