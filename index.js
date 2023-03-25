import express from 'express';
import path from 'path';
import mongoose from "mongoose";
import cookieParser from 'cookie-parser';
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const app = express();

//Setting EJS engine
app.set("view engine", "ejs");

//using middlewares
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());

//connect to mongodb server
mongoose.connect("mongodb://127.0.0.1:27017/Backend", {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("Database connected successfully");
}).catch((error) => {
    console.log("Error connecting mongoDB", error);
});

//create a user Schema
const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "Name not entered"]
    },
    email: {
        type: String,
        required: [true, "Email not entered"]
    },
    password: {
        type: String,
        required: [true, "Password not entered"]
    }
});

//create a new model
const User = mongoose.model("User", userSchema);

const isAuthenticated = async (req, res, next) => {
    const {token} = req.cookies;
    if (token) {
        const decoded = jwt.verify(token, "thisIsMyWeirdSECRETkey");
        req.user = await User.findById(decoded.id);
        next();
    }
    else {
        res.render("login");
    }
}

app.get("/", isAuthenticated, (req, res) => {
    res.render("logout", {name: req.user.name});
});

app.get("/login", isAuthenticated, (req, res) => {
    res.render("logout", {name: req.user.name});
});

app.get("/logout", (req, res) => {
    res.cookie("token", null, {
        httpOnly: true,
        expires: new Date(Date.now()),
    });
    res.redirect("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/login", async (req, res) => {
    const {email, password} = req.body;

    let user = await User.findOne({email});
    if(!user){
        return res.redirect("/register");
    }

    const isMatched = await bcrypt.compare(password, user.password);

    if(!isMatched) {
        return res.render("login", {email: email, message: "Incorrect password"});
    }

    const token = jwt.sign(
        {id: user._id,},
        "thisIsMyWeirdSECRETkey"
    );

    res.cookie(
        "token", 
        token, 
        {
            httpOnly: true,
            expires: new Date(Date.now() + 60000),
        }
    );

    res.redirect("/");
});

app.post("/register", async (req, res) => {
    const {name, email, password} = req.body;

    let user = await User.findOne({ email });

    if (user) {
        return res.redirect("/login");
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    user = await User.create({
        name, 
        email, 
        password: hashedPassword
    });

    const token = jwt.sign(
        {id: user._id,},            //this is called payload
        "thisIsMyWeirdSECRETkey"    //this is called secret string
    );

    res.cookie(
        "token",
        token,
        {
            httpOnly: true,
            expires: new Date(Date.now() + 60000),
        }
    );
    
    res.redirect("/");

});

app.listen(3000, (req, res) => {
    console.log("Server running on localhost:3000");
});