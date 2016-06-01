var express = require('express');
var morgan = require('morgan');

var passport = require('passport'); 
var cookieParser = require('cookie-parser');
var session = require('express-session');

var app = express();

var port = process.env.VCAP_APP_PORT || 5000;

// view engine setup - configure
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

 // define middleware
app.use(express.static(__dirname + '/views'));
app.use(morgan('dev')); // log every request to the console

app.use(cookieParser());
app.use(session({resave: 'true', saveUninitialized: 'true' , secret: 'keyboard cat'}));
app.use(passport.initialize());
app.use(passport.session()); 

passport.serializeUser(function(user, done) {
   done(null, user);
}); 

passport.deserializeUser(function(obj, done) {
   done(null, obj);
});         

// VCAP_SERVICES contains all the credentials of services bound to
// this application. For details of its content, please refer to
// the document or sample of each service.  
var services = JSON.parse(process.env.VCAP_SERVICES || "{}");
var ssoConfig = services.SingleSignOn[0]; 
var client_id = ssoConfig.credentials.clientId;
var client_secret = ssoConfig.credentials.secret;
var authorization_url = ssoConfig.credentials.authorizationEndpointUrl;
var token_url = ssoConfig.credentials.tokenEndpointUrl;
var issuer_id = ssoConfig.credentials.issuerIdentifier;
var callback_url = 'https://admin-demosso.mybluemix.net:443/auth/sso/callback';        

var OpenIDConnectStrategy = require('passport-idaas-openidconnect').IDaaSOIDCStrategy;
var Strategy = new OpenIDConnectStrategy({
                 authorizationURL : authorization_url,
                 tokenURL : token_url,
                 clientID : client_id,
                 scope: 'openid',
                 response_type: 'code',
                 clientSecret : client_secret,
                 callbackURL : callback_url,
                 skipUserProfile: true,
                 issuer: issuer_id}, 
	function(iss, sub, profile, accessToken, refreshToken, params, done)  {
	         	process.nextTick(function() {
		profile.accessToken = accessToken;
		profile.refreshToken = refreshToken;
		done(null, profile);
         	})
}); 

passport.use(Strategy); 
app.get('/login', passport.authenticate('openidconnect', {})); 
          
function ensureAuthenticated(req, res, next) {
	if(!req.isAuthenticated()) {
	          	req.session.originalUrl = req.originalUrl;
		res.redirect('/login');
	} else {
		return next();
	}
}

//define my route
app.get('/*', ensureAuthenticated, function(req, res) {
	res.render('admin');
});

app.get('/auth/sso/callback',function(req,res,next) {               
             var redirect_url = req.session.originalUrl;                
             passport.authenticate('openidconnect', {
                     successRedirect: redirect_url,                                
                     failureRedirect: '/failure',                        
          })(req,res,next);
        });

app.get('/failure', function(req, res) { 
             res.send('login failed'); });

app.listen(port);

console.log('Admin Service launched! Listening on port '+ port);