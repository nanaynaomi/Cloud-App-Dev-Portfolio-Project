const express = require('express');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
const ds = require('./datastore');
const datastore = ds.datastore;
const bodyParser = require('body-parser');
const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const BOAT = "Boat";
const LOAD = "Load";
const USER = "User";
const router = express.Router();
const hb = require('express-handlebars');
var dotenv = require('dotenv'); // Load environment variables from .env
var session = require('express-session');
var passport = require('passport');
var Auth0Strategy = require('passport-auth0');
var userInViews = require('./lib/middleware/userInViews');
var authRouter = require('./routes/auth');
var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
const BOATS_PATH = '/boats'
const LOADS_PATH = '/loads'

dotenv.config();

// Configure Passport to use Auth0
var strategy = new Auth0Strategy(
    {
      domain: process.env.AUTH0_DOMAIN,
      clientID: process.env.AUTH0_CLIENT_ID,
      clientSecret: process.env.AUTH0_CLIENT_SECRET,
      callbackURL: process.env.AUTH0_CALLBACK_URL || 'https://hw9-grantn.uw.r.appspot.com/callback'
    },
    function (accessToken, refreshToken, extraParams, profile, done) {
      // accessToken is the token to call Auth0 API (not needed in the most cases)
      // extraParams.id_token has the JSON Web Token
      // profile has all the information from the user
      return done(null, {...profile, id_token: extraParams.id_token});
    }
);
  
passport.use(strategy);

// You can use this section to keep a smaller payload
passport.serializeUser(function (user, done) {
    done(null, user);
});
  
passport.deserializeUser(function (user, done) {
    done(null, user);
});

const app = express();

app.set('view engine', 'handlebars');
app.use(express.static('public')); // Pull all style files from the public directory
app.engine('handlebars', hb({
    layoutsDir: __dirname + '/views/layouts'
}));
app.set('view options', {
    layout: 'main'
});

app.use(logger('dev'));
app.use(cookieParser());

// config express-session
var sess = {
  secret: 'MEOW MEOW SHHH SECRET AHHHH fgyhjiughdjrhfyd8484yy84yhfi',
  cookie: {},
  resave: false,
  saveUninitialized: true
};

if (app.get('env') === 'production') {
  // Use secure cookies in production (requires SSL/TLS)
  sess.cookie.secure = true;

  // Uncomment the line below if your application is behind a proxy (like on Heroku)
  // or if you're encountering the error message:
  // "Unable to verify authorization request state"
  app.set('trust proxy', 1);
}

app.use(session(sess));

app.use(passport.initialize());
app.use(passport.session());

app.use(userInViews());
app.use('/', authRouter);
app.use('/', indexRouter);
app.use('/', usersRouter);

const DOMAIN = 'cs493-grantn.us.auth0.com';

app.use(bodyParser.json());

app.set('trust proxy', true); 



/*
Gets our public key from that jwksUri which is provided to us by auth0.
It's a public key for our particular api and this is so we can check for validity of tokens...
So we include this in our requests and it will only continue on if the token is valid.
*/
const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${DOMAIN}/.well-known/jwks.json`
    }),
  
    // Validate the audience and the issuer.
    issuer: `https://${DOMAIN}/`,
    algorithms: ['RS256']
});

/* ------------- Begin Boat Model Functions ------------- */
function post_boat(name, type, length, owner){                              // POST /boats
    var key = datastore.key(BOAT);
	const new_boat = {"name": name, "type": type, "length": length, "owner":owner};
	return datastore.save({"key":key, "data":new_boat})
    .then(() => {
        new_boat["id"] = key["id"]; 
        return new_boat;
    });
}


function get_boats(req){                                                    // GET /boats
    var q = datastore.createQuery(BOAT).filter('owner', '=', req.user.sub).limit(5);   // limit result set to 5
    const query = datastore.createQuery(BOAT).filter('owner', '=', req.user.sub);
    const results = {};                                 // results set
    if(Object.keys(req.query).includes("cursor")){      // if this query includes a cursor in the query string
        q = q.start(req.query.cursor);                  // set the start point of our query to that cursor location and so if we've already gotten 2 results, then it will set the start to begin just after that, so we'll get the third and fourth result. You can't move the cursor forward or backwards, and that's why we can't have prev link
    } 
    return datastore.runQuery(query).then( (data) => {
        results.total_items = data[0].length;

        return datastore.runQuery(q).then( (entities) => {  // run query and get entities
            results.items = entities[0].map(ds.fromDatastore); //.filter(item => (item.owner === req.user.sub));   // our entities are stored in the 0th index in a set of results that include things like the cursor and if there are more results
            results.items.forEach(item => (item["self"] = req.protocol + "://" + req.get("host") + BOATS_PATH + '/' + item.id));
            if(entities[1].moreResults !== ds.Datastore.NO_MORE_RESULTS ){  // we look at the info about the query which is stored in the first index. One of the properties it has is the more results property. and there are constants we can get like the no more results constant. So if those are equal it means that there are no more results. If they're NOT equal (!==) that means there ARE more results.                                
                results.next = req.protocol + "://" + req.get("host") + BOATS_PATH + "?cursor=" + entities[1].endCursor; // We build the "next" link.
            }  
            return results;
        });
    });
}


function get_boat(boat_id, owner) {                                                 // GET /boat/:boat_id
    const key = datastore.key([BOAT, parseInt(boat_id, 10)]);
    return datastore.get(key).then((data) => {
        if (data[0] === undefined || data[0] === null) {
            return 'No boat with this boat_id exists';
        } else if (data[0].owner && data[0].owner !== owner) {
            return 'This boat is owned by someone else';
        } else {
            return data.map(ds.fromDatastore);
        }
    });
}


function patch_boat(id, boat, owner){                                //  PATCH - Edit a boat
    const key = datastore.key([BOAT, parseInt(id,10)]);
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return 'No boat with this boat_id exists';
        } else if (entity[0].owner && entity[0].owner !== owner) {
            return 'This boat is owned by someone else';
        }
        const updated_boat = {
            "name": entity[0].name, 
            "type": entity[0].type, 
            "length": entity[0].length,
            "owner": entity[0].owner,
            "loads": entity[0].loads
        };
        if (boat.name !== undefined && boat.name !== null) {
            updated_boat.name = boat.name;
        }
        if (boat.type !== undefined && boat.type !== null){
            updated_boat.type = boat.type;
        }
        if (boat.length !== undefined && boat.length !== null){
            updated_boat.length = boat.length;
        }
        return datastore.save({ "key": key, "data": updated_boat })
        .then(() => { 
            updated_boat["id"] = key["id"];
            return updated_boat;
        });
    });
}


function put_boat(id, name, type, length, owner){     //  PUT - Edit a boat
    const key = datastore.key([BOAT, parseInt(id, 10)]); 
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return 'No boat with this boat_id exists';
        } else if (entity[0].owner && entity[0].owner !== owner) {
            return 'This boat is owned by someone else';
        }  
        const updated_boat = {
            "name": name, 
            "type": type, 
            "length": length,
            "owner": entity[0].owner,
            "loads": entity[0].loads
        };
        return datastore.save({ "key": key, "data": updated_boat })
        .then(() => { 
            updated_boat["id"] = key["id"];
            return updated_boat;
        });
    });
}


function delete_boat(boat_id, owner){
    const b_key = datastore.key([BOAT, parseInt(boat_id,10)]);
    return datastore.get(b_key)
    .then( (data) => {
        const boat = data[0];
        if (boat === undefined || boat === null) {
            return 'No boat with this boat_id exists';
        } else if (boat.owner && boat.owner !== owner.sub) {
            return 'This boat is owned by someone else';
        } else if (boat.loads === undefined || boat.loads === null || boat.loads.length === 0){
            return datastore.delete(b_key);
        }     
        for (let i = 0; i < boat.loads.length; i++) {
            const l_key = datastore.key([LOAD, parseInt(boat.loads[i].id, 10)]);
            datastore.get(l_key).then((load) => {
                load[0].carrier = null;
                datastore.save({"key": l_key, "data": load[0]});
            });
        }
        return datastore.delete(b_key);  
    });
}



// LOADS:


function post_load(volume, content, creation_date){                           // Create a Load
    var key = datastore.key(LOAD);
	const new_load = {"volume": volume, "content": content, "creation_date": creation_date};
	return datastore.save({"key":key, "data":new_load})
        .then(() => {
            new_load["id"] = key["id"];
            return new_load;
        });
}

function get_loads(req){
    var q = datastore.createQuery(LOAD).limit(5);
    const query = datastore.createQuery(LOAD);
    const results = {};
    var prev;
    if(Object.keys(req.query).includes("cursor")){
        prev = req.protocol + "://" + req.get("host") + LOADS_PATH + "?cursor=" + req.query.cursor;
        q = q.start(req.query.cursor);
    }
    return datastore.runQuery(query).then( (data) => {
        results.total_items = data[0].length;
        return datastore.runQuery(q).then( (entities) => {
            results.items = entities[0].map(ds.fromDatastore);
            results.items.forEach(item => (item["self"] = req.protocol + "://" + req.get("host") + LOADS_PATH + '/' + item.id));
            if(typeof prev !== 'undefined'){
                results.previous = prev;
            }
            if(entities[1].moreResults !== ds.Datastore.NO_MORE_RESULTS ){
                results.next = req.protocol + "://" + req.get("host") + LOADS_PATH + "?cursor=" + entities[1].endCursor;            
            }
            return results;
        });
    });
}


function get_load(id) {                                                     //  View a load
    const key = datastore.key([LOAD, parseInt(id, 10)]);
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return entity;
        } else {
            return entity.map(ds.fromDatastore);
        }
    });
}


function patch_load(id, load){                                //  PATCH - Edit a load
    const key = datastore.key([LOAD, parseInt(id,10)]);
    return datastore.get(key).then((entity) => {
        if (entity[0] === undefined || entity[0] === null) {
            return 404;
        }
        const updated_load = {
            "volume": entity[0].volume, 
            "content": entity[0].content, 
            "creation_date": entity[0].creation_date,
            "carrier": entity[0].carrier
        };
        if (load.volume !== undefined && load.volume !== null) {
            updated_load.volume = load.volume;
        }
        if (load.content !== undefined && load.content !== null){
            updated_load.content = load.content;
        }
        if (load.creation_date !== undefined && load.creation_date !== null){
            updated_load.creation_date = load.creation_date;
        }
        return datastore.save({ "key": key, "data": updated_load })
        .then(() => { 
            updated_load["id"] = key["id"]; 
            return updated_load;
        });
    });
}

function put_load(id, volume, content, creation_date){                                  // PUT - Edit a load
    const key = datastore.key([LOAD, parseInt(id, 10)]);
    return datastore.get(key).then((entity) => {
        const load = {
            "volume": volume, 
            "content": content, 
            "creation_date": creation_date,
            "carrier": entity[0].carrier
        }; 
        if (entity[0] === undefined || entity[0] === null) {
            return 404;
        }
        return datastore.save({ "key": key, "data": load })
        .then(() => { 
            load["id"] = key["id"];
            return load;
        });
    });
}



function delete_load(lid) {                                                     // Delete a load
    const load_key = datastore.key([LOAD, parseInt(lid, 10)]);
    return datastore.get(load_key)
    .then((entity) => {
        const load = entity[0];
        if (load === undefined || load === null) {
            return 404;
        }
        if (load.carrier === null || load.carrier === undefined){
            return datastore.delete(load_key);
        }
        
        b_key = datastore.key([BOAT, parseInt(load.carrier.id, 10)]);
        const updated_loads = [];
        
        datastore.get(b_key).then(boats => {
            const boat = boats[0];            
            for (let i = 0; i < boat.loads.length; i++) {
                if (boat.loads[i].id !== lid){
                    updated_loads.push(boat.loads[i]);
                }
            }
            boat.loads = updated_loads;
            datastore.save({"key":b_key, "data":boat})
        });
        return datastore.delete(load_key);
    });          
}


function assign_load_to_boat(bid, lid, boat_owner){
    const b_key = datastore.key([BOAT, parseInt(bid,10)]); 
    const l_key = datastore.key([LOAD, parseInt(lid, 10)]);
    const lid_obj = {"id": lid};
    const keys = [l_key, b_key];
    return datastore.get(keys).then((data) => {
        const entities = data[0];
        const boat = entities[0];
        const load = entities[1];
        if (load === undefined || load === null || boat === undefined || boat === null) {
            return 404;
        }
        else if ((boat.name === undefined || boat.name === null) && load.name !== undefined){ // making sure boat is boat and load is load...
            boat = load;
            load = entities[0];
        }
        else if (boat.owner && boat.owner !== boat_owner) {
            return 'This boat is owned by someone else';
        } 
        else if ( typeof(boat.loads) === 'undefined'){  // check to see if there are any loads already. If there are no loads:
            boat.loads = [];    // if there are no loads, then we set the loads to be an empty array.
        }
        if (load.carrier !== undefined && load.carrier !== null){
            return 'The load is already assigned to a boat';     // Already assigned to a boat
        }
        boat.loads.push(lid_obj); 
        load["carrier"] = {"id": bid, "name": boat.name}; 
        return datastore.save({"key":b_key, "data":boat})
        .then(() => {return datastore.save({"key": l_key, "data": load})});
    });
}


function remove_load_from_boat(bid, lid, boat_owner){
    const b_key = datastore.key([BOAT, parseInt(bid, 10)]);
    const l_key = datastore.key([LOAD, parseInt(lid, 10)]);    
    const keys = [l_key, b_key];
    return datastore.get(keys).then((data) => {
        const boat = data[0][0];
        const load = data[0][1];
        if (load === undefined || load === null || boat === undefined || boat === null) {
            return 404;
        }
        else if ((boat.name === undefined || boat.name === null) && load.name !== undefined){ // making sure boat is boat and load is load...
            boat = load;
            load = data[0][0];
        }
        else if (boat.owner && boat.owner !== boat_owner) {
            return 'This boat is owned by someone else';
        }      
        let load_on_boat = false;
        const updated_loads = [];
        for (let i = 0; i < boat.loads.length; i++) {
            if (boat.loads[i].id !== lid){
                updated_loads.push(boat.loads[i]);
            } else {
                load_on_boat = true;
            }
        }
        if (!load_on_boat) {
            return 404;
        }
        else {
            load.carrier = null;
            boat.loads = updated_loads;
            return datastore.save({"key":b_key, "data":boat})
            .then(() => {return datastore.save({"key": l_key, "data": load})});
        }
    });
}


/* ===== USERS ====== */

function get_users(){
    const q = datastore.createQuery(USER);
    return datastore.runQuery(q).then((entities) => {
        return entities[0].map(ds.fromDatastore);
    });
}


/* ------------- End Model Functions ------------- */

function check_jwt(){
    return [
        checkJwt,
        function(err, req, res, next){
            if (err){
                res.status(401).json({'Error': 'Missing or invalid JWT'});
            }
        }
    ]
}

/* ------------- Begin Controller Functions ------------- */

// POST - Create a Boat
router.post('/boats', check_jwt(), function(req, res){    
    const accepts = req.accepts(['application/json']);                              // POST /boats
    if (req.body.name === undefined || req.body.type === undefined || req.body.length === undefined) {
        res.status(400).json({ 'Error': "The request object is missing at least one of the required attributes"});
    } else if (!accepts){
        res.status(406).json({'Error': 'Not an acceptable MIME type'});
    } else {
        post_boat(req.body.name, req.body.type, req.body.length, req.user.sub)
        .then( new_boat => {
            res.status(201).json({
                "id": new_boat.id,
                "name": new_boat.name,
                "type": new_boat.type,
                "length": new_boat.length,
                "owner": new_boat.owner,
                "self": req.protocol + "://" + req.get("host") + '/boats' + '/' + new_boat.id
            })
        });
    }
});

// GET - Get Boats
router.get('/boats', check_jwt(), function(req, res){                                   // GET /boats
    const boats = get_boats(req)
	.then( (boats) => {
        const accepts = req.accepts(['application/json']);
        if(!accepts){
            res.status(406).json({'Error': 'Not an acceptable MIME type'});
        } else {
            res.status(200).json(boats);
        }
    });
});


router.get('/boats/:boat_id', check_jwt(), function (req, res) {                        // GET /boats/:boat_id
    get_boat(req.params.boat_id, req.user.sub)
        .then(boat => {
            const accepts = req.accepts(['application/json']);
            if(!accepts){
                res.status(406).json({'Error': 'Not an acceptable MIME type'});
            } else if (typeof boat === 'string'){
                res.status(403).json({'Error': boat});
            } else {
                const loads = [];                
                if (boat[0].loads) {
                    const loads = boat[0].loads;
                    loads.forEach(load => { 
                        load["self"] = req.protocol + '://' + req.get("host") + '/loads/' + load.id 
                    });
                }
                res.status(200).json({
                    "id": boat[0].id,
                    "name": boat[0].name,
                    "type": boat[0].type,
                    "length": boat[0].length,
                    "owner": boat[0].owner,
                    "loads": boat[0].loads,
                    "self": req.protocol + '://' + req.get("host") + '/boats/' + boat[0].id
                });
            }
        });
});


//  PATCH - Edit a boat
router.patch('/boats/:boat_id', check_jwt(), function(req, res){                             // PATCH /boats/:boat_id  (Edit a boat)
    const accepts = req.accepts(['application/json']);
    if(!accepts){
        res.status(406).json({'Error': 'Not an acceptable MIME type'});
    } else if (req.body.name === undefined && req.body.type === undefined && req.body.length === undefined) {
        res.status(400).json({ 'Error': "The request object requires at least one of the following attributes: name, type, or length"});
    } else {
        patch_boat(req.params.boat_id, req.body, req.user.sub)
        .then(updated_boat => {
            if (typeof updated_boat === 'string'){
                res.status(403).json({'Error': updated_boat});
            } else {
                const loads = [];                
                if (updated_boat.loads) {
                    const loads = updated_boat.loads;
                    loads.forEach(load => { 
                        load["self"] = req.protocol + '://' + req.get("host") + '/loads/' + load.id 
                    });
                }
                res.status(200).json({
                    "id": updated_boat.id,
                    "name": updated_boat.name,
                    "type": updated_boat.type,
                    "length": updated_boat.length,
                    "owner": updated_boat.owner,
                    "loads": updated_boat.loads,
                    "self": req.protocol + "://" + req.get("host") + BOATS_PATH + '/' + updated_boat.id
                })
            }
        });
    }
});


// 4. PUT - Edit a boat
router.put('/boats/:boat_id', check_jwt(), function(req, res){                              // PUT /boats/:boat_id  (Edit a boat)
    const accepts = req.accepts(['application/json']);
    if (req.body.name === undefined || req.body.type === undefined || req.body.length === undefined) {
        res.status(400).json({ 'Error': "The request object is missing at least one of the required attributes"});
    } else if (!accepts){
        res.status(406).json({'Error': 'Not an acceptable MIME type'});
    } else {
        put_boat(req.params.boat_id, req.body.name, req.body.type, req.body.length, req.user.sub)
        .then(updated_boat => {
            if (typeof updated_boat === 'string'){
                res.status(403).json({'Error': updated_boat});
            } else {
                const loads = [];                
                if (updated_boat.loads) {
                    const loads = updated_boat.loads;
                    loads.forEach(load => { 
                        load["self"] = req.protocol + '://' + req.get("host") + '/loads/' + load.id 
                    });
                }
                res.status(200).json({
                    "id": updated_boat.id,
                    "name": updated_boat.name,
                    "type": updated_boat.type,
                    "length": updated_boat.length,
                    "owner": updated_boat.owner,
                    "loads": updated_boat.loads,
                    "self": req.protocol + "://" + req.get("host") + BOATS_PATH + '/' + updated_boat.id
                })
            }
        });
    }
});

router.delete('/boats/:boat_id', check_jwt(), function(req, res){        // DELETE /boats/:boat_id
    delete_boat(req.params.boat_id, req.user)
    .then( (boat_error) => {
        if (typeof boat_error === 'string'){
            res.status(403).json({'Error': boat_error});
        } else {
            res.status(204).end();
        }
    });
});


router.delete('/boats', function (req, res){
    res.set('Accept', 'POST, GET');
    res.status(405).end();
});
router.put('/boats', function (req, res){
    res.set('Accept', 'POST, GET');
    res.status(405).end();
});
router.patch('/boats', function (req, res){
    res.set('Accept', 'POST, GET');
    res.status(405).end();
});

/* -----  LOADS ------ */

// POST - Create a load                                                         // POST /loads
router.post('/loads', function (req, res) {
    const accepts = req.accepts(['application/json']);
    if (req.body.volume === undefined || req.body.content === undefined || req.body.creation_date === undefined) {
        res.status(400).json({ 'Error': "The request object is missing at least one of the required attributes"});
    } else if(!accepts){
        res.status(406).json({'Error': 'Not an acceptable MIME type'});
    } else {
        post_load(req.body.volume, req.body.content, req.body.creation_date)
        .then(new_load => {
            res.status(201).json({
                "id": new_load.id,
                "volume": new_load.volume,
                "content": new_load.content,
                "creation_date": new_load.creation_date,
                "self": req.protocol + "://" + req.get("host") + LOADS_PATH + '/' + new_load.id
            })
        });
    }
});

router.get('/loads', function(req, res){
    const loads = get_loads(req)
	.then( (loads) => {
        const accepts = req.accepts(['application/json']);
        if(!accepts){
            res.status(406).json({'Error': 'Not an acceptable MIME type'});
        } else {
            res.status(200).json(loads);
        }
    });
});


router.get('/loads/:load_id', function (req, res) {                              // View a load
    get_load(req.params.load_id)
    .then(load => {
        const accepts = req.accepts(['application/json']);
        if(!accepts){
            res.status(406).json({'Error': 'Not an acceptable MIME type'});
        } else if (load[0] === undefined || load[0] === null) {
            res.status(404).json({ 'Error': 'No load with this load_id exists' });
        } else {             
            if (load[0].carrier) {
                load[0].carrier["self"] = req.protocol + '://' + req.get("host") + '/boats/' + load[0].carrier.id;
            }
            res.status(200).json({
                "id": load[0].id,
                "volume": load[0].volume,
                "carrier": load[0].carrier,                    
                "content": load[0].content,
                "creation_date": load[0].creation_date,
                "self": req.protocol + '://' + req.get("host") + LOADS_PATH + '/' + load[0].id
            });
        }
    });
});


//  PATCH - Edit a load
router.patch('/loads/:load_id', function(req, res){                      // PATCH /loads/:load_id  (Edit a load)
    const accepts = req.accepts(['application/json']);
    if(!accepts){
        res.status(406).json({'Error': 'Not an acceptable MIME type'});
    } else if (req.body.volume === undefined && req.body.type === undefined && req.body.creation_date === undefined) {
        res.status(400).json({ 'Error': "The request object requires at least one of the following attributes: volume, type, or creation_date"});
    } else {
        patch_load(req.params.load_id, req.body)
        .then(updated_load => {
            if (updated_load === 404){
                res.status(404).json({'Error': 'No load with this load_id exists'})
            } else {
                const carrier = null;                
                if (updated_load.carrier) {
                    const carrier = updated_load.carrier;
                    carrier["self"] = req.protocol + '://' + req.get("host") + '/boats/' + carrier.id;
                }
                res.status(200).json({
                    "id": updated_load.id,
                    "volume": updated_load.volume,
                    "content": updated_load.content,
                    "creation_date": updated_load.creation_date,
                    "carrier": updated_load.carrier,
                    "self": req.protocol + "://" + req.get("host") + LOADS_PATH + '/' + updated_load.id
                })
            }
        });
    }
});


//  PUT - Edit a load
router.put('/loads/:load_id', function(req, res){                     // PUT /loads/:load_id  (Edit a load)
    const accepts = req.accepts(['application/json']);
    if (req.body.volume === undefined || req.body.content === undefined || req.body.creation_date === undefined) {
        res.status(400).json({ 'Error': "The request object is missing at least one of the required attributes"});
    } 
    else if (!accepts){
        res.status(406).json({'Error': 'Not an acceptable MIME type'});
    } else {
        put_load(req.params.load_id, req.body.volume, req.body.content, req.body.creation_date)
        .then(updated_load => {
            if (updated_load === 404){
                res.status(404).json({'Error': 'No load with this load_id exists'})
            } else {
                const carrier = null;                
                if (updated_load.carrier) {
                    const carrier = updated_load.carrier;
                    carrier["self"] = req.protocol + '://' + req.get("host") + '/boats/' + carrier.id;
                }
                res.status(200).json({
                    "id": updated_load.id,
                    "volume": updated_load.volume,
                    "content": updated_load.content,
                    "creation_date": updated_load.creation_date,
                    "carrier": updated_load.carrier,
                    "self": req.protocol + "://" + req.get("host") + LOADS_PATH + '/' + updated_load.id
                })
            }
        });
    }
});


router.delete('/loads/:load_id', function (req, res) {
    delete_load(req.params.load_id)
        .then(load_status => {
            if (load_status === 404){
                res.status(404).json({ 'Error': 'No load with this load_id exists' });
            } else {
                res.status(204).end();
            }            
        });
});

router.delete('/loads', function (req, res){  
    res.set('Accept', 'POST, GET');
    res.status(405).end();
});
router.put('/loads', function (req, res){ 
    res.set('Accept', 'POST, GET');
    res.status(405).end();
});
router.patch('/loads', function (req, res){      
    res.set('Accept', 'POST, GET');
    res.status(405).end();
});


/* ----------------- */

router.put('/boats/:boat_id/loads/:load_id', check_jwt(), function(req, res){                  // Assign Load to Boat
    assign_load_to_boat(req.params.boat_id, req.params.load_id, req.user.sub)
    .then(boat_status => {
        if (boat_status === 404){
            res.status(404).json({ 'Error': 'The specified boat and/or load does not exist' });
        } 
        else if (typeof boat_status === 'string'){
            res.status(403).json({'Error': boat_status});
        }
        else {
            res.status(204).end();
        }  
    });
});

// Remove load from boat
router.delete('/boats/:boat_id/loads/:load_id', check_jwt(), function(req, res){                  // Remove load from boat
    remove_load_from_boat(req.params.boat_id, req.params.load_id, req.user.sub)
    .then(boat_status => {
        if (boat_status === 404){
            res.status(404).json({ 'Error': 'A boat with this boat_id does not contain a load with this load_id' });
        } 
        else if (typeof boat_status === 'string'){
            res.status(403).json({'Error': boat_status});
        }
        else {
            res.status(204).end();
        }
    });         
});


// GET /users  ----------------

router.get('/users', function(req, res){
    const users = get_users()
	.then( (users) => {
        res.status(200).json(users);
    });
});


/* ------------- End Controller Functions ------------- */

app.use('/', router);

// Listen to the App Engine-specified port
const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});
