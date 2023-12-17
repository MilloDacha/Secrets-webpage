import "dotenv/config";
import express, { response } from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import localPassport from "passport-local";
import session from "express-session";
import passportGoogleOauth from "passport-google-oauth20";

const port = 3000;
const app = express();
const db = new pg.Client({
    user: process.env.USER,
    host: process.env.HOST,
    database: process.env.DATABASE,
    password: "dachaNomo#SQL",
    port: process.env.PORT,
});
db.connect();
const localStrategy = localPassport.Strategy;
const GoogleStrategy = passportGoogleOauth.Strategy;

app.set("view engine","ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));
app.use(session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},async (acessToken, refreshToken, profile, done)=>{
    try{
        const response = await db.query("SELECT * FROM users WHERE googleID = $1",[profile.id]);
        if(response.rows.length===0){
            await db.query("INSERT INTO users (googleID) VALUES ($1)",[profile.id]);
            const newResponse = await db.query("SELECT * FROM users WHERE googleID = $1",[profile.id]);
            const user = newResponse.rows[0];
            return done(null, user);
        }
        else{
            const user = response.rows[0];
            return done(null, user);
        }
    }
    catch(error){
        return done(error, false);
    }
}));

passport.use("local-register",new localStrategy(async (username,password,done)=>{
    try{
        const result = await db.query("SELECT * FROM users WHERE email = $1",[username]);
        const user = result.rows[0];
        if(user!==undefined){
            return done(null, false);
        }
        else{
            const hashedPass = await bcrypt.hash(password,10);
            await db.query("INSERT INTO users (email, password) VALUES ($1,$2)",[username,hashedPass]);
            const newResult = await db.query("SELECT * FROM users WHERE email = $1",[username]);
            const newUser = newResult.rows[0];
            return done(null, newUser);
        }
    }
    catch(error){
        return done(error, false);   
    }
}));
passport.use("local-login",new localStrategy(async (username,password,done)=>{
    try{
        const result = await db.query("SELECT * FROM users WHERE email = $1",[username]);
        const user = result.rows[0];
        if(user!==undefined){
            const passCheck = await bcrypt.compare(password, user.password);
            if(passCheck){
                return done(null, user);
            }
            else{
                return done(null, false);
            }
        }
        else{
            return done(null, false);
        }
    }
    catch(error){
        return done(error,false);
    }   
}));

passport.serializeUser((user,done)=>{
    done(null,user.id);
});
passport.deserializeUser(async (id,done)=>{
    try{
        const response = await db.query("SELECT * FROM users WHERE id = $1",[id]);
        const user = response.rows[0];
        done(null,user);
    }
    catch (error){
        done(error,false);
    }
});

app.get("/",async (req,res)=>{
    res.render("home.ejs");
});

app.get("/register",(req,res)=>{
    res.render("register.ejs");
});
app.post("/register", passport.authenticate("local-register",{
    failureRedirect: "/register",
    successRedirect: "/secrets",
}));

app.get("/login",(req,res)=>{
    res.render("login.ejs");
});
app.post("/login", passport.authenticate("local-login",{
    failureRedirect: "/login",
    successRedirect: "/secrets",
}));

app.get("/auth/google", passport.authenticate("google",{
    scope: ["profile"]
}));
app.get("/auth/google/secrets", passport.authenticate("google",{
    failureRedirect: "/register",
    successRedirect: "/secrets",
}));

app.get("/submit",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("submit.ejs");
    }
    else{
        res.redirect("/register");
    }
});
app.post("/submit",async (req,res)=>{
    try{
        const userSecret = req.body.secret;
        const userId = req.user.id;
        await db.query("UPDATE users SET secret = $1 WHERE id = $2",[userSecret,userId]);
        res.redirect("/secrets");
    }
    catch(error){
        res.redirect("/submit");
    }
});

app.get("/secrets",async (req,res)=>{
    try{
        const response = await db.query("SELECT secret FROM users");
        const userSecrets = response.rows;
        res.render("secrets.ejs",{data: userSecrets});
    }
    catch(error){
        res.redirect("/");
    }
});

app.get("/logout",(req,res)=>{
    res.clearCookie("connect.sid");
    req.logOut(()=>{
        res.redirect("/");
    });
});

app.listen(port,()=>{
    console.log(`The server is running on port ${port}`);
});