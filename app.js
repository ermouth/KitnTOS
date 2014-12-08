/**
 * Module dependencies.
 */
require('sugar');
var env = require('jsdom').env;
var fs = require('fs'),
    fetch = require('fetch');


var express = require('express');
var cookieParser = require('cookie-parser');
var compress = require('compression');
var session = require('express-session');
var bodyParser = require('body-parser');
var logger = require('morgan');
var errorHandler = require('errorhandler');
var csrf = require('lusca').csrf();
var methodOverride = require('method-override');

var _ = require('lodash');
var MongoStore = require('connect-mongo')(session);
var flash = require('express-flash');
var path = require('path');
var mongoose = require('mongoose');
var passport = require('passport');
var expressValidator = require('express-validator');
var connectAssets = require('connect-assets');

/**
 * Controllers (route handlers).
 */

var homeController = require('./controllers/home');
var userController = require('./controllers/user');
var apiController = require('./controllers/api');
var contactController = require('./controllers/contact');
var kitntosController = require('./controllers/kitntos');

/**
 * API keys and Passport configuration.
 */

var secrets = require('./config/secrets');
var passportConf = require('./config/passport');

/**
 * Create Express server.
 */

var app = express();
var fe = {
      couch: {},
      lib: {},
      tmpls: {
        header: function (d) {
          var html = '';
          html +=
              '<!DOCTYPE html>'+
              '<html lang="en">'+
              '<head>'+
                  '<meta charset="utf-8">'+
                  '<title>Kit’n’tos</title>'+
                  '<!-- CSS first for correct pixel measuring during start -->'+
                  '<link rel="stylesheet" type="text/css" href="http://cdn.cloudwall.me/0.9/cw.general.css" />'+
                  '<link rel="stylesheet" type="text/css" href="http://cdn.cloudwall.me/0.9/cw.css" />'+
                  '<!-- Base libs -->'+
                  '<script src="http://cdn.cloudwall.me/0.9/cw.general.js"></script>'+
                  '<script src="http://cdn.cloudwall.me/0.9/pouchdb.js"></script>'+
                  '<script src="http://cdn.cloudwall.me/0.9/cw.plugins.js"></script>'+
                  //'<script>d ='+JSON.stringify(d||{})+'; console.log("tldr rows: ",d);</script>'+
              '</head>'+
              '<body >'+
              '<!-- Sidenotes container -->'+
              '<div id="cw-notes"></div>'+
              '<!-- Main frame -->'+
              '<div id="cw-body" style="width:1260px;color:rgba(71,81,95,1)">'
          return html;
        },
        footer: function (d) {
          var html = '';
          html +=
              '</div>'+
              '</body>'+
              '<style>'+
                  'input[type=text], input[type=password], input[type=number], input[type=date], input[type=time], select[multiple]'+
                  '{ padding: 0.4em 0.5em; }'+
                  '.mt70 {margin-top:70px;}'+
                  '.mt80 {margin-top:80px;}'+
                  '.mt90 {margin-top:90px;}'+
                  '.mt120 {margin-top:120px;}'+
                  '.mt150 {margin-top:150px;}'+
                  '.bw2 {border-width:2px!important}'+
                  '#kt-landing a:hover, #kt-landing .pseudolink:hover {color: #FF4159;}'+
              '</style>'+
              '</html>'
          return html;
        }
      }
    },
    cw = fe;
var P = {
  fe: {
    // GENERAL PARAMS
    buckets:{
      // real dbs to system aliasing
      main:"kitntos"
    },

    "headers": {
      "*":{
          "Access-Control-Allow-Credentials":true,
          "Access-Control-Allow-Origin":"*",
          "Access-Control-Expose-Headers":"Content-Type, Server",
          "Access-Control-Allow-Headers":"Content-Type, Server",
          "Access-Control-Max-Age":"86400"
      }
    }
  }
};

var kt = {fe: fe, P: P};
require("./fe.lib")(kt);

/**
 * Connect to MongoDB.
 */

mongoose.connect(secrets.db);
mongoose.connection.on('error', function() {
  console.error('MongoDB Connection Error. Please make sure that MongoDB is running.');
});

/**
 * Connect to CouchDB
 */
var nano = require('nano');
    ktdb = nano({ "url": "http://127.0.0.1:5984/"+ P.fe.buckets.main});

/**
 * CSRF whitelist.
 */

//var csrfExclude = ['/url1', '/url2', '/doc'];

/**
 * Express configuration.
 */

app.set('port', process.env.PORT || 80);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(compress());

/** Set CORS headers */
app.use(function(req, res, next){
    res.set(P.fe.headers["*"]);
    next();
});

app.use(connectAssets({
  paths: [path.join(__dirname, 'public/css'),
    path.join(__dirname, 'public/js')]
}));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(expressValidator());
app.use(methodOverride());
app.use(cookieParser());
app.use(session({
  resave: true,
  saveUninitialized: true,
  secret: secrets.sessionSecret,
  store: new MongoStore({ url: secrets.db, auto_reconnect: true })
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
//app.use(function(req, res, next) {
//  // CSRF protection.
//  if (_.contains(csrfExclude, req.path)) return next();
//  csrf(req, res, next);
//});
app.use(function(req, res, next) {
  // Make user object available in templates.
  res.locals.user = req.user;
  //console.log(req.user);
  next();
});
app.use(function(req, res, next) {
  // Remember original destination before login.

  var path = req.path.split('/')[1];
    console.log('PPPAAAATH: ', path);
  if (/auth|login|logout|signup|fonts|favicon|img|css|js|doc|pd|new|all/i.test(path)||path=='i') {
    return next();
  }
  req.session.returnTo = req.path;
  next();
});
app.use(express.static(path.join(__dirname, 'public'), { maxAge: 31557600000 }));

/**
 * Main routes.
 */

//app.get('/', homeController.index);

//get tldr
//app.get(/^\/-[a-z0-9]{8}$/, ktGetDocPage);

//get json-data for some tldr
//app.post('/doc', passportConf.isAuthenticated, ktGetDoc);
app.post('/doc', ktGetDoc);
app.post('/all', ktGetAll);

//get user data json
app.get('/pd', passportConf.isAuthenticated, userController.getAccountPD);

//create new doc
app.post('/new', passportConf.isAuthenticated, ktNewTldr);

//set vote
app.post('/vote', passportConf.isAuthenticated, ktSetVote);


//default routes
app.get('/login', userController.getLogin);
app.post('/login', userController.postLogin);
app.get('/logout', userController.logout);
app.get('/forgot', userController.getForgot);
app.post('/forgot', userController.postForgot);
app.get('/reset/:token', userController.getReset);
app.post('/reset/:token', userController.postReset);
app.get('/signup', userController.getSignup);
app.post('/signup', userController.postSignup);
app.get('/contact', contactController.getContact);
app.post('/contact', contactController.postContact);
app.get('/account', passportConf.isAuthenticated, userController.getAccount);
app.post('/account/profile', passportConf.isAuthenticated, userController.postUpdateProfile);
app.post('/account/password', passportConf.isAuthenticated, userController.postUpdatePassword);
app.post('/account/delete', passportConf.isAuthenticated, userController.postDeleteAccount);
app.get('/account/unlink/:provider', passportConf.isAuthenticated, userController.getOauthUnlink);

/**
 * API examples routes.
 */

app.get('/api', apiController.getApi);
app.get('/api/lastfm', apiController.getLastfm);
app.get('/api/nyt', apiController.getNewYorkTimes);
app.get('/api/aviary', apiController.getAviary);
app.get('/api/steam', apiController.getSteam);
app.get('/api/stripe', apiController.getStripe);
app.post('/api/stripe', apiController.postStripe);
app.get('/api/scraping', apiController.getScraping);
app.get('/api/twilio', apiController.getTwilio);
app.post('/api/twilio', apiController.postTwilio);
app.get('/api/clockwork', apiController.getClockwork);
app.post('/api/clockwork', apiController.postClockwork);
app.get('/api/foursquare', passportConf.isAuthenticated, passportConf.isAuthorized, apiController.getFoursquare);
app.get('/api/tumblr', passportConf.isAuthenticated, passportConf.isAuthorized, apiController.getTumblr);
app.get('/api/facebook', passportConf.isAuthenticated, passportConf.isAuthorized, apiController.getFacebook);
app.get('/api/github', passportConf.isAuthenticated, passportConf.isAuthorized, apiController.getGithub);
app.get('/api/twitter', passportConf.isAuthenticated, passportConf.isAuthorized, apiController.getTwitter);
app.post('/api/twitter', passportConf.isAuthenticated, passportConf.isAuthorized, apiController.postTwitter);
app.get('/api/venmo', passportConf.isAuthenticated, passportConf.isAuthorized, apiController.getVenmo);
app.post('/api/venmo', passportConf.isAuthenticated, passportConf.isAuthorized, apiController.postVenmo);
app.get('/api/linkedin', passportConf.isAuthenticated, passportConf.isAuthorized, apiController.getLinkedin);
app.get('/api/instagram', passportConf.isAuthenticated, passportConf.isAuthorized, apiController.getInstagram);
app.get('/api/yahoo', apiController.getYahoo);

/**
 * OAuth sign-in routes.
 */

app.get('/auth/instagram', passport.authenticate('instagram'));
app.get('/auth/instagram/callback', passport.authenticate('instagram', { failureRedirect: '/login' }), function(req, res) {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
app.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/' }), function(req, res) {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/github', passport.authenticate('github'));
app.get('/auth/github/callback', passport.authenticate('github', { failureRedirect: '/' }), function(req, res) {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/google', passport.authenticate('google', { scope: 'profile email' }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), function(req, res) {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/twitter', passport.authenticate('twitter'));
app.get('/auth/twitter/callback', passport.authenticate('twitter', { failureRedirect: '/' }), function(req, res) {
  res.redirect(req.session.returnTo || '/');
});
app.get('/auth/linkedin', passport.authenticate('linkedin', { state: 'SOME STATE' }));
app.get('/auth/linkedin/callback', passport.authenticate('linkedin', { failureRedirect: '/' }), function(req, res) {
  res.redirect(req.session.returnTo || '/');
});

/**
 * OAuth authorization routes for API examples.
 */

app.get('/auth/foursquare', passport.authorize('foursquare'));
app.get('/auth/foursquare/callback', passport.authorize('foursquare', { failureRedirect: '/api' }), function(req, res) {
  res.redirect('/api/foursquare');
});
app.get('/auth/tumblr', passport.authorize('tumblr'));
app.get('/auth/tumblr/callback', passport.authorize('tumblr', { failureRedirect: '/api' }), function(req, res) {
  res.redirect('/api/tumblr');
});
app.get('/auth/venmo', passport.authorize('venmo', { scope: 'make_payments access_profile access_balance access_email access_phone' }));
app.get('/auth/venmo/callback', passport.authorize('venmo', { failureRedirect: '/api' }), function(req, res) {
  res.redirect('/api/venmo');
});

/**
 * 500 Error Handler.
 */

app.use(errorHandler());

app.use(function(req, res, next){
    res.status(404);

    // respond with html page
    if (req.accepts('html')) {
        var html = '';
        html += fe.tmpls.header()+
            '<div style="text-align: center;margin-top: 100px;">' +
                '<a href="/"><img src="/i/logo.png" class="w170"></a><h3 style="margin-top: 20px;">404: No such kitten, sorry.</h3>'+
                '<h3><a href="/">Main page</a></h3>'+
            '</div>'+
        fe.tmpls.footer();

        res.send(html,404);
        return;
        //render404(function(html){
        //    res.send(html);
        //    return;
        //});
    }

    // respond with json
    if (req.accepts('json')) {
        res.send({ error: 'Not found' });
        return;
    }

    // default to plain-text. send()
    res.type('txt').send('Not found');
});

/**
 * Start Express server.
 */

app.listen(app.get('port'), function() {
  console.log('Express server listening on port %d in %s mode', app.get('port'), app.get('env'));
});

module.exports = app;


/*###################################*/
/*### route functions for kitntos ###*/

/**
 * GET /-hid8hid8
 * get doc hid and render page
 */
function ktGetDocPage (req, res) {
    try {
        var hid = req.url.slice(2);

        getTldrRows({view: "getTldrByHid", key: hid}, function (err, data) {
            if (err) {
                res.sendStatus(404);
            }
            else {
                renderTldr(data, function (err, data) {
                    if (err) res.send(503);
                    else res.send(data);
                });
            }
        });
    } catch(e){
            res.json({'error': 503, 'message': 'Server error.'});
        }
}

function renderTldr (data, callback) {
    try {
        var data = data || {},
            html = '',
            tldr = data.rows[0],
            fragments = tldr.fragments ? tldr.fragments : [];

        html += fe.tmpls.header(tldr) +
        '<div>' +
        '<h3>' + tldr.name + '</h3>' +
        fragments.reduce(function (html, key) {
            return html + key.html
        }, '') +
        '</div>' +
        fe.tmpls.footer();

        callback(null, html);
    } catch(e){
        callback({'error': 503, 'message': 'Server error.'},null);
    }
}


/**
 * POST /doc
 * get tldr
 * @param: url || hid
 */
function ktGetDoc (req, res) {
    try {
        var url = req.body.url || "", hid = req.body.hid || "",
            key = url ? url : hid,
            view = url ? 'getTldrByUrl' : 'getTldrByHid';

        //console.log('url', req.body.url);
        getTldrRows({view: view, key: key}, function (err, data) {
            if (err) {
                if (err.error == "none" && !hid) {
                    fetchTldr(url, function (err, data) {
                        if (err) {
                            res.json({
                                'error': 404,
                                'message': err
                            });
                        }
                        else {
                            res.json({
                                'error': 400,
                                'message': 'Doc not found',
                                rows: [{
                                    name: data[1],
                                    url: url,
                                    hid: fe.lib.hash8(clearUrl(url)),
                                    fragments: data[0]
                                }]
                            });
                        }
                    })
                }
                else if (hid) res.json({'error': 404, 'message': 'Document not found.'});
                else res.json({
                        'error': err.statusCode || 503,
                        'message': err.reason || err.error || 'Server error.'
                    });
            }
            else {
                res.json({'ok': 200, rows: data.rows, count: data.count, sum: data.sum});
            }
        });
    } catch(e){
        res.json({'error': 503, 'message': 'Server error.'});
    }
}

function ktGetAll (req, res) {
    try {
        ktdb.view("all", 'docsByStamp', {
            startkey: -Date.now(),
            endkey: 0,
            limit: 100
        }, function (err, data) {
            if (err) res.json({
                'error': err.statusCode || 503,
                'message': err.reason || err.error || 'Server error.'
            });
            else {
                var docs = data.rows,
                    docsHids = [],
                    docsRows = [],
                    all = {};
                for (var i = 0; i < docs.length; i++) {
                    docsHids.push(docs[i].value.hid);
                    docsRows.push(docs[i].value);
                }

                //get  counts
                ktdb.view("all", 'allCounts', {
                    group: true,
                    keys: docsHids
                }, function (err, data) {
                    if (err) res.json({
                        'error': err.statusCode || 503,
                        'message': err.reason || err.error || 'Server error.'
                    });
                    else {
                        ktCounts = data.rows ? data.rows : [];

                        //get sum
                        ktdb.view("all", 'allSum', {
                            group: true,
                            keys: docsHids
                        }, function (err, data) {
                            if (err) res.json({
                                'error': err.statusCode || 503,
                                'message': err.reason || err.error || 'Server error.'
                            });
                            else {
                                ktSum = data.rows ? data.rows : [];
                                res.json({'ok': 200, rows: docsRows, count: ktCounts, sum: ktSum});
                            }
                        })
                    }
                });
            }
        })
    } catch(e){
        res.json({'error': 503, 'message': 'Server error.'});
    }
}

function getTldrRows (data, callback) {
    try {
        ktdb.view("all", data.view, {key: data.key, limit: 1}, function (err, data) {
            if (err) callback(err, null);
            else if (data.rows && !data.rows.length) callback({error: 'none'}, null);
            else {
                var tldr,
                    ktCounts,
                    ktSum;
                tldr = data.rows[0].value;

                //get tldr fragments counts
                ktdb.view("all", 'kitnsCounts', {
                    group: true,
                    startkey: [tldr.hid, ""],
                    endkey: [tldr.hid, "z"]
                }, function (err, data) {
                    if (err) callback(err, null);
                    else {
                        ktCounts = data.rows ? data.rows : [];
                        ktdb.view("all", 'kitnsSum', {
                            group: true,
                            startkey: [tldr.hid, ""],
                            endkey: [tldr.hid, "z"]
                        }, function (err, data) {
                            if (err) callback(err, null);
                            else {
                                ktSum = data.rows ? data.rows : [];
                                callback(null, {rows: [tldr], count: ktCounts, sum: ktSum});
                            }
                        })
                    }
                });
            }
        });
    } catch(e){
        callback({'error': 503, 'message': 'Server error.'}, null);
    }
}

function fetchTldr (url, callback){
    try {
        tldrParser(url, function (err, data) {
            if (err) {
                console.log('err', err);
                callback('Can’t load requested URL', null);
            }
            else {
                console.log('data', data[0]);
                callback(null, data);
            }
        });
    } catch(e){
        callback({'error': 503, 'message': 'Server error.'}, null);
    }
}

/**
 * clear url: delete hash, http:// https://, last slash if exist
 */
function clearUrl (d) {
  //return d.split('#')[0].replace(//);
  return d.split('#')[0].replace(/https?\:\/\//,'').replace(/^(.*)\/$/,'$1');
}

/**
 * POST /new
 * create new TLDR
 *
 * { url:"", hid:"", name:"", tags:[array of tags], old:"" }
 */
function ktNewTldr (req, res) {
    var doc = req.body||{},
        view = 'getTldrByUrl',
        key = doc.url,
        url = doc.url,
        newdoc = {
            url: doc.url,
            hid: fe.lib.hash8(clearUrl(doc.url)),
            name: doc.name||doc.url.replace(/^http[s]?:\/\//,'').split("/")[0].split(".").reverse().to(2).reverse().join(".").capitalize(),
            tags: doc.tags,
            creator: req.user.email||req.user._id,
            stamp: Date.now(),
            created: Date.now(),
            old: doc.old||"",
            kitn: 0,
            type: 'tldr'
        };
    console.log('create new tldr');
    getTldrRows({view: view, key: key}, function(err, data){
        if (err) {
            if (err.error == "none") {
                fetchTldr(doc.url, function(err, data){
                    if (err) {
                        res.json({
                            'error':404,
                            'message': err
                        });
                    }
                    else {
                        newdoc.fragments = data[0];
                        ktdb.insert(newdoc, function(err, data) {
                            /**
                             * data[0] -- array of fragments
                             * data[1] -- tldr name
                             */
                            if (err) res.json({'error': err.statusCode||503, 'message': err.reason||err.error||'Server error.'});
                            else {
                                res.json({'ok':200, rows: [newdoc], count: [], sum: []});

                            }
                        });
                    }
                })
            }
            else res.json({'error':err.statusCode||503, 'message': err.reason||err.error||'Server error.'});
        }
        else {
            res.json({'error':503, 'message': 'Document already exist.'});
        }
    });
}

/**
 * POST /vote
 * create new or update old vote
 *
 */
function ktSetVote (req, res) {
    try {
  var doc = req.body||{},
      newdoc = {
        type:"kitten",
        creator:req.user.email||req.user._id,
        created:Date.now(),
        stamp:Date.now(),
        parent:doc.id,			             // parent doc _id
        hid:doc.hid, 	                     // parent docgroup hid
        fragment: doc.fid,	                 // fragment id
        kitn: doc.kitn*1,		             // vote, 1…5
        desc: (doc.desc||"").truncate(60)	  // description, if it was one
      };
        ktdb.view("all", "fragments", {key: [doc.id, doc.fid]}, function (err, data) {
            if (err) {
                res.json({'error': err.statusCode || 503, 'message': err.reason || err.error || 'Server error.'});
            }
            else {
                console.log('fragments rows: ', data.rows.length);
                if (data.rows && data.rows.length) {

                    var fragmentDoc = data.rows[0].value;
                    //check if vote exist or not
                    ktdb.view("all", "votesByCreator", {key: [req.user.email || req.user._id, doc.fid]}, function (err, data) {
                        if (err) {
                            res.json({
                                'error': err.statusCode || 503,
                                'message': err.reason || err.error || 'Server error.'
                            });
                        }
                        else {
                            if (data.rows && data.rows.length) {
                                var vote = data.rows[0].value;

                                //update vote
                                ktdb.atomic("all", "vote", vote._id,
                                    newdoc, function (err, data) {
                                        console.log('update vote!');
                                        console.log('err: ', err);
                                        console.log('data: ', data);
                                        if (err) res.json({
                                            'error': err.statusCode || 503,
                                            'message': err.reason || err.error || 'Server error.'
                                        });
                                        else if (data && data.error) res.json({
                                            'error': data.statusCode || 503,
                                            'message': data.reason || data.error || 'Server error.'
                                        });
                                        else {
                                            //update fragment
                                            var partTldr = {
                                                _id: newdoc.parent,
                                                stamp: newdoc.stamp,
                                                fragment: {
                                                    id: newdoc.fragment,
                                                    stamp: newdoc.stamp,
                                                    desc: newdoc.desc
                                                }
                                            }
                                            console.log('partTldr: ', partTldr);
                                            updateFragment(partTldr, function (err, data) {
                                                if (err) res.json({
                                                    'error': err.statusCode || 503,
                                                    'message': err.reason || err.error || 'Server error.'
                                                });
                                                else {
                                                    newFragments = data.fragments || [];
                                                    calcFragmentVotes({hid: newdoc.hid, fragment: newdoc.fragment},
                                                        function (err, data) {
                                                            if (err) res.json({
                                                                'error': err.statusCode || 503,
                                                                'message': err.reason || err.error || 'Server error.'
                                                            });
                                                            else {
                                                                res.json({
                                                                    ok: 200,
                                                                    kitn: data.kitn,
                                                                    fragments: newFragments
                                                                })
                                                            }
                                                        })
                                                }
                                            })
                                        }
                                    });
                            }
                            else {

                                //create new vote
                                ktdb.insert(newdoc, function (err, data) {
                                    if (err) res.json({
                                        'error': err.statusCode || 503,
                                        'message': err.reason || err.error || 'Server error.'
                                    });
                                    else {
                                        //todo: check new fragments
                                        var partTldr = {
                                            _id: newdoc.parent,
                                            stamp: newdoc.stamp,
                                            fragment: {
                                                id: newdoc.fragment,
                                                stamp: newdoc.stamp,
                                                desc: newdoc.desc
                                            }
                                        }
                                        console.log('partTldr: ', partTldr);
                                        updateFragment(partTldr, function (err, data) {
                                            if (err) res.json({
                                                'error': err.statusCode || 503,
                                                'message': err.reason || err.error || 'Server error.'
                                            });
                                            else {
                                                newFragments = data.fragments || [];
                                                calcFragmentVotes({hid: newdoc.hid, fragment: newdoc.fragment},
                                                    function (err, data) {
                                                        if (err) res.json({
                                                            'error': err.statusCode || 503,
                                                            'message': err.reason || err.error || 'Server error.'
                                                        });
                                                        else {
                                                            res.json({
                                                                ok: 200,
                                                                kitn: data.kitn,
                                                                fragments: newFragments
                                                            })
                                                    }
                                                });
                                        }
                                    });
                                }
                            });
                        }
                    }
                });
            }
            else {
                res.json({error:404, message:'Fragment not found.'});
            }
        }
    });
    } catch(e){
        res.json({'error': 503, 'message': 'Server error.'});
}
}

function updateFragment (data, callback){
    try {
    ktdb.atomic("all", "fragment", data._id,
        data, function (err, data) {
            if (err) callback(err, null);
            else if (data && data.error) callback(data, null);
            else {
                callback(null, data);
            }
        })
    } catch(e){
        callback({'error': 503, 'message': 'Server error.'}, null);
}
}

/**
 * calc votes for fragment
 */
function calcFragmentVotes(d0, callback) {
    try {
    var d = d0||{};

    ktdb.view("all",'kitnsCounts', {
        group:true,
        key:[d.hid, d.fragment]
        }, function(err, data) {

            if (err) callback(err,null);
            else if (data.rows && data.rows.length) {
                console.log('counts');
                console.log(data);
                ktCounts = data.rows[0].value||1;
                ktdb.view("all",'kitnsSum', {
                    group:true,
                    key:[d.hid, d.fragment]
                    }, function(err, data) {
                    if (err) callback(err,null);
                    else if (data.rows && data.rows.length) {
                        console.log('sum');
                        console.log(data);
                        ktSum = data.rows[0].value||0;
                        var average = (ktSum/ktCounts).round(1);
                        callback(null,{kitn:average});
                    }
                    else callback({'statusCode':503,'message':'Not found vote counts'},null);
                })
            }
            else callback({'statusCode':503,'message':'Not found vote counts'},null);
    });
    } catch(e){
        callback({'error': 503, 'message': 'Server error.'}, null);
}
}


/**
 * html parser
 */

function tldrParser (url, callback){
    try {
    getPage(url, function(err, body) {
        if (err) return callback('Downlaod html error', null);
        else {
            try {
                env(body, function (errors, window) {
                    console.log('errors', errors);
                    var $ = require('jquery')(window),
                        html = $('body').size() ?
                        '<body>' + $('body').html() + '</body>' :
                        '<html>' + $('html').html() + '</html>';


                    // Parser-prettifier

                    // TODO!
                    // — convert relative links
                    // – convert CAPS CASE to Sentence case
                    // — convert #local links to spans
                    // ✔︎ remove attrs style, class, onload, onclick – at least

                    var $t, $f, $f1, $f2, $res, $res0, resl, $preparsed,
                        $o = $(html.removeTags([
                            "script", "object", "embed", "style", "font", "input", "button", "textarea", "form", "fieldset",
                            "noscript", "iframe"
                        ]).stripTags(["blockquote", "font"])),
                        depth = 3;

                    // Strip wrappers, find meat.
                    // Approach seems ok – find most long parent of Hn.
                    // To determine appropriate n we check if next level is at least 3x longer.

                    function _getBody(depth) {

                        ["h2", "h1"].forEach(function (tag) {
                            $f = $o.find(tag);
                            $t = $f.parents();
                            var $c;
                            $t.each(function (i, e) {
                                if (!$c && i < depth) {
                                    var $tree = $(e),
                                        treel = $tree.text().length;
                                    if (treel > 5000) {
                                        $c = $tree;
                                            if (!$res || treel > resl * 4) {
                                                $res = $tree;
                                                resl = treel;
                                        }
                                    }
                                    }
                            });
                        });
                    }

                    _getBody(depth);
                    if (!$res) {
                        depth = 6;
                        _getBody(depth);
                    }
                    if ($res) $res0 = $res.clone();
                    try {
                        if ($res) {

                            // $res now contains only TL;DR markup, no wrappers, navs etc.
                            // We must flatten it – remove redundant containers.
                            // To do it we use similar approach – if container is too long,
                            // it’s content must be unwrapped.
                            // We must make several passes over src DOM tree.

                            (4).times(function () {
                                $t = $res.children();
                                $t.each(function (i, e) {
                                    var $tree = $(e),
                                        treel = $tree.text().length;
                                    if (treel > resl / 2) {
                                        $tree.children().insertAfter($tree);
                                        $tree.remove();
                                    }
                                });
                            });


                            // Next we must rebuild DOM tree replacing first level children tags
                            // with div, h2 and h3 only

                            $f = $('<div></div>'); // create new tree

                            function _parseChild(i, e, $f) {
                                var ctag = e.tagName.toLowerCase(),
                                    tag = 'div',
                                    $tree = $(e),
                                    html = $tree.html(),
                                    txt = $tree.text().compact(),
                                    treel = txt.length;
                                if (ctag == "br") html = "";
                                else if (/^h\d$/.test(ctag)) {
                                    tag = ctag;
                                    html = txt;
                                }
                                else if (ctag == 'pre') html = html.replace(/[\r\n]+/g, '; ');
                                else {

                                    // Try to guess if it’s a head
                                    if (/^([A-ZА-Я0-9\s,;]{1,100}[^\.;,])$/.test(txt)
                                        || (txt.length < 50 && !/[\.;,]$/.test(txt) && !/<a/.test(html))) {
                                        tag = 'h3';
                                        html = txt;
                                    }
                                }

                                if (html) $('<' + tag + '>' + html + '</' + tag + '>').appendTo($f);
                            }


                            $res.children().each(_parseChild.fill(undefined, undefined, $f));


                            // Now we must unfold divs with rich inner content.
                            // They can contain textNodes mixed with both block
                            // and inline markup, so it's tricky.

                            function _unfoldMarkup(i, e, nodelist) {
                                // nodelist is comma-separated list of tags to uplevel
                                var $tree = $(e);
                                if ($tree.is("div") && $tree.find(nodelist).size()) {
                                    var html = '',
                                        atag = '',
                                        $list = $tree.contents();
                                    $list.each(function (i, e) {
                                        var t = e.nodeType, ctag;
                                        if (t == 1) {
                                            // we have tag
                                            ctag = e.tagName.toLowerCase();

                                            if (ctag == "br") {
                                                if (atag == "div") html += '</div><div>';
                                                else html += '<br>';
                                            }

                                            else if (ctag == "ol") {
                                                if (atag == "div") html += '</div>';
                                                var ctr = 1;
                                                $(e).children().each(function (i, e) {
                                                    if ($(e).html()) {
                                                        html += '<div>' + ctr + ". " + $(e).html() + '</div>';
                                                        ctr += 1;
                                                    }
                                                });
                                                if (atag == "div") html += '<div>';
                                            }

                                            else if (ctag == "ul") {
                                                if (atag == "div") html += '</div>';
                                                $(e).children().each(function (i, e) {
                                                    if ($(e).html()) {
                                                        html += '<div>&middot; ' + $(e).html() + '</div>';
                                                    }
                                                });
                                                if (atag == "div") html += '<div>';
                                            }

                                            else if (/^(div|p)$/.test(ctag)) {
                                                if (atag == "div") html += '</div>';
                                                html += '<div>' + $(e).html() + '</div>';
                                                if (atag == "div") html += '<div>';
                                            }

                                            else if (/^h\d$/.test(ctag)) {
                                                if (atag == "div") html += '</div>';
                                                html += '<' + ctag + '>' + $(e).html() + '</' + ctag + '>';
                                                if (atag == "div") html += '<div>';
                                            }

                                            else {
                                                html += e.outerHTML;
                                            }
                                        }
                                        else if (t == 3) {
                                            // we have textNode
                                            if (atag != 'div') {
                                                if (atag) html += '</' + atag + '>';
                                                atag = 'div';
                                                html += '<div>';
                                            }
                                            html += e.nodeValue + " ";
                                        }
                                    });

                                    if (atag == "div") html += '</div>';

                                    html.replace(/(<br>[\r\n\t\s]*)+/g, '<br>');
                                    $tree.replaceWith($(html));
                                }
                            }

                            // Unfold markup twice with diff sets of tags to uplevel

                            $f.children().each(_unfoldMarkup.fill(undefined, undefined, 'br,li,ol,ul,div,p,h1,h2,h3'));
                            var prevhtml = cw.lib.sdbm($f.html());

                            $f.children().each(_unfoldMarkup.fill(undefined, undefined, 'br,div,p,h1,h2,h3'));
                            var currhtml = cw.lib.sdbm($f.html()),
                                ctr = 0;

                            // Unfold even deeper if needed
                            while (ctr < depth && currhtml != prevhtml) {
                                $f.children().each(_unfoldMarkup.fill(undefined, undefined, 'div,p,h1,h2,h3'));
                                currhtml = cw.lib.sdbm($f.html());
                                ctr += 1;
                            }

                            // Reparse for headers
                            $f1 = $('<div></div>'); // create new tree
                            $f.children().each(_parseChild.fill(undefined, undefined, $f1));

                            // Determine H max level and correct it to H2, H3, H4
                            var cr = [], hrepl = {}, shift = 0;
                            if ($f1.find("h1").size()) cr.push("h1");
                            if ($f1.find("h2").size()) cr.push("h2");
                            if ($f1.find("h3").size()) cr.push("h3");
                            for (var i = 0; i < cr.length; i++) hrepl[cr[i]] = "h" + (i + 2);
                            $f1.children().each(function (i, e) {
                                var ctag = e.tagName.toLowerCase(),
                                    t = hrepl[ctag];
                                if (t) $(e).replaceWith($(['<', t, '>', $(e).html(), '</', t, '>'].join('')));
                            });

                            // Replace obese sections (caps plus bold)
                            $f1.find("b,em,strong").each(function (i, e) {
                                var txt = $(e).text().compact();
                                if (txt.replace(/[A-ZА-Я]/g, '').length < txt.length * 0.7) {
                                    $(e).replaceWith($('<span>' + $(e).html() + '</span>'));
                                }
                            });

                            // Next we must convert it to obj
                            var fragments = [], headermet = false;
                            $f1.children().each(function (i, e) {
                                var ctag = e.tagName.toLowerCase(),
                                    html = $(e).html(),
                                    obj;
                                obj = {
                                    id: cw.lib.sdbm(Date.now() + html),
                                    type: ctag,
                                    stamp: Date.now(),
                                    html: html,
                                    kitn: 0,
                                    desc: ""
                                };
                                // Strip preface if any
                                if (/^(h1|h2)$/.test(ctag) || headermet) fragments.push(obj);
                                if (/^(h1|h2)$/.test(ctag)) headermet = true;
                            });

                            //Remove attrs
                            ["class", "style", "onload", "onclick"].forEach(function (attr) {
                                $f1.find("*[" + attr + "]").each(function (i, e) {
                                    $(e).removeAttr(attr);
                                });
                            });

                            // Gen title
                            if (fragments) {
                            var domain = (url||"").replace(/^http[s]?:\/\//,'').split("/")[0].split(".").reverse().to(2).reverse().join(".").capitalize(),
                                    title = (domain?domain+": ":"")+fragments[0].html;
                                fragments.shift();
                            }

                            return callback(null, [fragments||[],title||""]);
                        }
                        else {
                            return callback('Parse html error', null);
                        }
                    } catch (e) {
                        console.log(e);
                        return callback(e, null);
                    }
                })
            }
            catch(e) {
                return callback(e, null);
            }
        }
    });
    } catch(e){
        callback({'error': 503, 'message': 'Server error.'},null);
    }
};

/**
 * Downlad html by url
 * @param url
 * @param callback
 */
function getPage (url, callback) {
    try {
    fetch.fetchUrl(url, {
        timeout:3000,
        headers: {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1944.0 Safari/537.36"
        }
    }, function(error, meta, body){
        if (error) console.log("Fetched error!",error);
        else console.log("Fetched " +url+ " OK!");
        callback(error,body.toString());
    });
    } catch(e){
        callback({'error': 503, 'message': 'Server error.'},null);
    }
}