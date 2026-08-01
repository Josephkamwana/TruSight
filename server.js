require("dotenv").config();

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const axios = require("axios");
const dns = require("dns").promises;
const { URL } = require("url");

const useragent = require("useragent");
const whois = require("whois-json");
const sslChecker = require("ssl-checker");

const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const csrf = require("csurf");
const cors = require("cors");

const { Low } = require("lowdb");
const { JSONFile } = require("lowdb/node");

const app = express();

const NODE_ENV = process.env.NODE_ENV || "production";

// ==========================
// DATABASE
// ==========================

const adapter = new JSONFile("database.json");

const defaultData = {
    users: [],
    links: [],
    logs: [],
    reports: [],
    ipCache: {}
};

const db = new Low(adapter, defaultData);

let dbLock = false;

async function safeWrite() {

    while (dbLock) {
        await new Promise(resolve => setTimeout(resolve, 10));
    }

    dbLock = true;

    try {
        await db.write();
    } finally {
        dbLock = false;
    }
}

async function initDatabase() {

    await db.read();

    db.data ||= defaultData;

    await safeWrite();

    console.log("Database loaded");
}


// ==========================
// SECURITY
// ==========================

app.set("trust proxy", 1);

app.use(cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true
}));

app.use(
    helmet({
        contentSecurityPolicy: false
    })
);

app.use(cookieParser());

app.use(express.json({
    limit: "1mb"
}));

app.use(express.static("."));


// ==========================
// RATE LIMIT
// ==========================

const requests = {};

app.use((req, res, next) => {

    const ip =
        req.headers["x-forwarded-for"]?.split(",")[0] ||
        req.socket.remoteAddress ||
        "unknown";

    const now = Date.now();

    if (!requests[ip]) {
        requests[ip] = [];
    }

    requests[ip] =
        requests[ip].filter(
            time => now - time < 60000
        );

    if (requests[ip].length > 100) {

        return res.status(429).json({
            success: false,
            message: "Too many requests"
        });

    }

    requests[ip].push(now);

    next();

});


// ==========================
// SESSION
// ==========================

app.use(session({

    secret:
        process.env.SESSION_SECRET ||
        "TruSight_9x8fK2mP91xQ7vL4zN0aR6sT3yW54_secure_keyrondomXr",

    resave: false,

    saveUninitialized: false,

    cookie: {

        httpOnly: true,

        secure: NODE_ENV === "production",

        sameSite: "lax",

        maxAge: 86400000

    }

}));


// ==========================
// CSRF
// ==========================

const csrfProtection = csrf({

    cookie: {

        httpOnly: true,

        secure: NODE_ENV === "production",

        sameSite: "strict"

    }

});


app.get(
    "/api/csrf-token",
    csrfProtection,
    (req, res) => {

        res.json({

            success: true,

            token: req.csrfToken()

        });

    }
);


// ==========================
// HELPERS
// ==========================

function genId() {

    return (
        Date.now() +
        "-" +
        crypto.randomBytes(4).toString("hex")
    );

}


function getClientIP(req) {

    return (
        req.headers["x-forwarded-for"]?.split(",")[0] ||
        req.socket.remoteAddress ||
        "Unknown"
    );

}


function getDomain(link) {

    try {

        return new URL(link).hostname;

    } catch {

        return "Unknown";

    }

}


function isValidURL(str) {

    try {

        const u = new URL(str);

        return (
            u.protocol === "http:" ||
            u.protocol === "https:"
        );

    } catch {

        return false;

    }

}


function isValidUsername(username) {

    return /^[a-zA-Z0-9_]{3,20}$/.test(username);

}


function isValidPassword(password) {

    return (
        typeof password === "string" &&
        password.length >= 6
    );

}
function getDeviceType(ua) {

    if (/android|iphone|mobile/i.test(ua)) {
        return "Phone";
    }

    if (/tablet|ipad/i.test(ua)) {
        return "Tablet";
    }

    return "Desktop";

}


function getDeviceInfo(req) {

    const ua =
        req.headers["user-agent"] || "Unknown";

    const agent =
        useragent.parse(ua);

    return {

        browser: agent.toAgent(),

        browserName: agent.family,

        os: agent.os.toString(),

        deviceType: getDeviceType(ua),

        language:
            req.headers["accept-language"] ||
            "Unknown",

        screen:
            req.body?.screen ||
            "Unknown",

        lastActive:
            new Date().toLocaleString()

    };

}


// ==========================
// AUTH MIDDLEWARE
// ==========================

function authRequired(req, res, next) {

    if (!req.session.user) {

        return res.status(401).json({

            success: false,

            message: "Login required"

        });

    }

    next();

}


function adminOnly(req, res, next) {

    if (
        !req.session.user ||
        req.session.user.role !== "admin"
    ) {

        return res.status(403).json({

            success: false,

            message: "Admin access required"

        });

    }

    next();

}


// ==========================
// LOG SYSTEM
// ==========================

async function saveLog(action, req = null) {

    try {

        await db.read();

        db.data.logs.push({

            id: genId(),

            action,

            type:
                action.split(":")[0],

            user:
                req?.session?.user?.username ||
                "System",

            ip:
                req ?
                getClientIP(req) :
                "System",

            time:
                new Date().toLocaleString()

        });


        await safeWrite();


    } catch (error) {

        console.log(
            "Log error:",
            error
        );

    }

}


// ==========================
// GEO LOCATION
// ==========================

async function getGeoInfo(ip) {


    if (
        ip.includes("127.0.0.1") ||
        ip.includes("::1")
    ) {

        return {

            country: "Local",

            city: "Localhost",

            isp: "Local"

        };

    }


    ip = ip.replace("::ffff:", "");


    try {


        const response =
            await axios.get(

                `http://ip-api.com/json/${ip}?fields=status,country,city,isp`,

                {
                    timeout: 5000
                }

            );


        if (
            response.data.status === "success"
        ) {


            return {

                country:
                    response.data.country,

                city:
                    response.data.city,

                isp:
                    response.data.isp

            };

        }


    } catch (error) {


    }


    return {

        country: "Unknown",

        city: "Unknown",

        isp: "Unknown"

    };


}


// ==========================
// REGISTER
// ==========================

app.post(
    "/register",
    async (req, res) => {

        try {

            const {
                username,
                password
            } = req.body;


            if (!isValidUsername(username)) {

                return res.json({

                    success: false,

                    message:
                        "Username must be 3-20 characters"

                });

            }


            if (!isValidPassword(password)) {

                return res.json({

                    success: false,

                    message:
                        "Password must be 6+ characters"

                });

            }


            await db.read();


            const exists =
                db.data.users.find(
                    user =>
                        user.username === username
                );


            if (exists) {

                return res.json({

                    success: false,

                    message:
                        "Username already exists"

                });

            }


            const hash =
                await bcrypt.hash(
                    password,
                    10
                );


            const geo =
                await getGeoInfo(
                    getClientIP(req)
                );


            db.data.users.push({

                id: genId(),

                username,

                password: hash,

                role: "user",

                status: "active",

                ip:
                    getClientIP(req),

                geo,

                device:
                    getDeviceInfo(req),

                created:
                    new Date().toLocaleString(),

                lastActive:
                    new Date().toLocaleString()

            });


            await safeWrite();


            await saveLog(
                `REGISTER: ${username}`,
                req
            );


            res.json({

                success: true,

                message:
                    "Account created"

            });


        } catch (error) {


            console.log(error);


            res.status(500).json({

                success: false,

                message:
                    "Server error"

            });


        }

    }
);
// ==========================
// LOGIN
// ==========================

app.post(
    "/login",
    async (req, res) => {

        try {

            const {
                username,
                password
            } = req.body;


            await db.read();


            const user =
                db.data.users.find(
                    u => u.username === username
                );


            if (!user) {

                return res.json({

                    success: false,

                    message:
                        "Invalid credentials"

                });

            }


            if (user.status === "suspended") {

                return res.json({

                    success: false,

                    message:
                        "Account suspended"

                });

            }


            const match =
                await bcrypt.compare(
                    password,
                    user.password
                );


            if (!match) {


                await saveLog(
                    `LOGIN_FAILED: ${username}`,
                    req
                );


                return res.json({

                    success: false,

                    message:
                        "Invalid credentials"

                });

            }


            user.ip =
                getClientIP(req);


            user.geo =
                await getGeoInfo(
                    user.ip
                );


            user.device =
                getDeviceInfo(req);


            user.lastActive =
                new Date().toLocaleString();


            await safeWrite();


            req.session.regenerate(
    async () => {

        req.session.user = {

            id: user.id,

            username:
                user.username,

            role:
                user.role

        };


        await saveLog(
            `LOGIN: ${username}`,
            req
        );


        req.session.save(() => {

            res.json({

                success: true,

                role:
                    user.role

            });

        });

    }
);



        } catch (error) {


            console.log(error);


            res.status(500).json({

                success:false,

                message:
                    "Server error"

            });


        }

    }
);


// ==========================
// LOGOUT
// ==========================

app.get(
    "/logout",
    (req, res) => {

        const username =
            req.session.user?.username;


        req.session.destroy(
            async () => {


                await saveLog(
                    `LOGOUT: ${username}`
                );


                res.json({

                    success:true

                });


            }
        );


    }
);


// ==========================
// CURRENT USER
// ==========================

app.get(
    "/api/me",
    (req, res) => {


        if (!req.session.user) {

            return res.json({

                loggedIn:false

            });

        }


        res.json({

            loggedIn:true,

            user:req.session.user

        });


    }
);


// ==========================
// CREATE FIRST ADMIN
// ==========================

app.post(
    "/create-admin",
    async (req,res)=>{


        try {


            await db.read();


            const adminExists =
                db.data.users.find(
                    u => u.role === "admin"
                );


            if(adminExists){

                return res.json({

                    success:false,

                    message:
                        "Admin already exists"

                });

            }


            const {
                username,
                password
            } = req.body;



            if(
                !isValidUsername(username) ||
                !isValidPassword(password)
            ){

                return res.json({

                    success:false,

                    message:
                        "Invalid details"

                });

            }


            const hash =
                await bcrypt.hash(
                    password,
                    10
                );


            db.data.users.push({

                id:genId(),

                username,

                password:hash,

                role:"admin",

                status:"active",

                created:
                    new Date().toLocaleString()

            });


            await safeWrite();


            res.json({

                success:true,

                message:
                    "Admin created"

            });



        } catch(error){


            console.log(error);


            res.status(500).json({

                success:false,

                message:
                    "Server error"

            });


        }


    }
);


// ==========================
// LINK ANALYSIS
// ==========================

async function analyzeLink(url){


    const domain =
        getDomain(url);


    let ip = "Unknown";

    let ssl = false;

    let registrar = "Unknown";

    let domainAge = 0;


    let threat =
        "No obvious threat found";


    try {


        const dnsData =
            await dns.resolve4(domain);


        ip =
            dnsData[0];


    } catch {}



    try {


        const cert =
            await sslChecker(domain);


        ssl =
            cert.valid;


    } catch {}



    try {


        const info =
            await whois(domain);


        registrar =
            info.registrar ||
            "Unknown";


        const created =
            info.creationDate ||
            info["Creation Date"];



        if(created){


            domainAge =
                Math.floor(

                    (Date.now() -
                    new Date(created))
                    /
                    (1000*60*60*24)

                );


        }


    } catch {}



    let score = 100;


    if(!url.startsWith("https")){

        score -= 30;

    }


    if(
        /login|verify|secure|account/i
        .test(domain)
    ){

        score -= 40;

        threat =
            "Possible Phishing";

    }


    if(
        /free|gift|prize/i
        .test(domain)
    ){

        score -= 20;

        threat =
            "Suspicious keywords detected";

    }


    if(score < 0)
        score = 0;



    await db.read();


    const old =
        db.data.links.find(
            l => l.url === url
        );


    return {

        url,

        domain,

        ip,

        ssl,

        registrar,

        domainAge,

        threat,

        reports:
            old?.reports || 0,

        safetyScore:
            score,

        threatCategory:
            score < 50 ?
            "Suspicious" :
            "Clean",

        checked:
            new Date().toLocaleString()

    };


}
// ==========================
// LINK SCAN
// ==========================

app.post(
    "/api/links",
    authRequired,
    csrfProtection,
    async (req,res)=>{

        try {


            const {url} = req.body;


            if(!isValidURL(url)){

                return res.json({

                    success:false,

                    message:
                        "Invalid URL"

                });

            }


            const analysis =
                await analyzeLink(url);



            await db.read();



            db.data.links.push({

                id:genId(),

                ...analysis,

                addedBy:
                    req.session.user.username,

                time:
                    new Date().toLocaleString()

            });



            await safeWrite();



            await saveLog(
                `LINK_SCAN: ${url}`,
                req
            );



            res.json({

                success:true,

                analysis

            });



        } catch(error){


            console.log(error);


            res.status(500).json({

                success:false,

                message:
                    "Server error"

            });


        }


    }
);


// ==========================
// INVESTIGATE
// ==========================

app.post(
    "/api/investigate",
    authRequired,
    csrfProtection,
    async(req,res)=>{


        try {


            const {url} = req.body;



            if(!isValidURL(url)){


                return res.json({

                    success:false,

                    message:
                        "Invalid URL"

                });


            }



            const result =
                await analyzeLink(url);



            await saveLog(
                `INVESTIGATE: ${url}`,
                req
            );



            res.json({

                success:true,

                result

            });



        } catch(error){


            console.log(error);


            res.status(500).json({

                success:false,

                message:
                    "Server error"

            });


        }


    }
);


// ==========================
// REPORT LINK
// ==========================

app.post(
    "/api/report-link",
    authRequired,
    csrfProtection,
    async(req,res)=>{


        try {


            const {
                url,
                reason
            } = req.body;



            if(
                !url ||
                !reason ||
                !isValidURL(url)
            ){

                return res.json({

                    success:false,

                    message:
                        "Invalid report details"

                });

            }



            await db.read();



            db.data.reports.push({

                id:genId(),

                url,

                reason,

                reportedBy:
                    req.session.user.username,

                time:
                    new Date().toLocaleString()

            });



            await safeWrite();



            await saveLog(
                `REPORT: ${url}`,
                req
            );



            res.json({

    success:true,

    message:
        "Report submitted"

});


        } catch(error){

            console.log(error);

            res.status(500).json({

                success:false,

                message:
                    "Server error"

            });

        }

    }

);

// ADMIN USERS ROUTE
app.get("/api/admin/users", authRequired, adminOnly, async (req,res)=>{

    await db.read();

    const users = db.data.users.map(user => ({

        username:user.username,
        role:user.role,
        status:user.status,

        ip:user.ip,

        country:user.geo?.country || "Unknown",
        city:user.geo?.city || "Unknown",
        isp:user.geo?.isp || "Unknown",

        device:user.device?.deviceType || "Unknown",
        browser:user.device?.browserName || "Unknown",
        os:user.device?.os || "Unknown",

        lastActive:user.lastActive

    }));

    res.json(users);

});


// ==========================
// START SERVER
// ==========================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`TruSight Backend running on port ${PORT}`);
});

        
