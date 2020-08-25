//configuración para acceder al .env
require('dotenv').config();
//declaración de solicitudes de los modulos requeridos
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

//inicialización de express-session
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

////inicialización y configuracion de passport
app.use(passport.initialize());
app.use(passport.session());

//conexión a MongoDB
mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true });
mongoose.set("useCreateIndex", true);

//configuración del esquema de la base de datos
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

//inicialización de passport-local-mongoose
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//modelo de usuario
const User = new mongoose.model("User", userSchema);

//configuración de passport
passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//autenticación de google
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https:/www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        console.log(profile);
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

//pagina de inicio
app.get("/", function (req, res) {
    res.render("home");
});

app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] }));

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function (req, res) {
        res.redirect('/secrets');
    });

//pagina de inicio de sesion
app.get("/login", function (req, res) {
    res.render("login");
});

// pagina de registro
app.get("/register", function (req, res) {
    res.render("register");
});

//verificacion de usuario
app.get("/secrets", function (req, res) {
    User.find({ "secret": { $ne: null } }, function (err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", { usersWithSecrets: foundUsers });
            }
        }
    });
});

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;

    console.log(req.user.id);

    User.findById(req.user.id, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function () {
                    res.redirect("/secrets");
                });
            }
        }
    })
});

app.get("/logout", function (req, res,) {
    req.logout();
    res.redirect("/");
});

//publicación de la pagina de registro
app.post("/register", function (req, res) {
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});

//publicación de la pagina de inicio de sesión
app.post("/login", function (req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.logIn(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});

//configuración del puerto del servidor   
app.listen(3000, function () {
    console.log("The server started on port 3000");
});
