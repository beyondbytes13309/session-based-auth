const express = require('express')
const bcrypt = require('bcrypt')
const cookieParser = require('cookie-parser')
const cors = require('cors')
require('dotenv').config()
const crypto = require('crypto')

// Setup the app
const app = express()
app.set('view engine', 'ejs')
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())

const USERS = new Map()
const SESSIONS = new Map()
USERS.set(1, {username: "emmar", password: "123"})
const sessionExpiryCheckRate = 5 * 60 * 1000 // 5 minutes
const sessionTime =  15 * 60 * 1000 // 15 minutes

// Setup helper functions

// Function to create and bind Ids and sending cookies
function setupIDs(res, userID) {
    const sessionID = crypto.randomBytes(16).toString('hex')
    SESSIONS.set(sessionID, {
        "userID": userID,
        "expiresAt": new Date(Date.now() + sessionTime) // 15 minutes
    })
    return res.cookie('sessionID', sessionID, {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax'
    })
}

// Function to check if session exists, is expired or not
function hasExpired(req) {
    const cookie = req.cookies.sessionID
    if(!cookie) {
        return {userID: null, code: 'nocookie'}; // cookie is not sent
    }

    const session = SESSIONS.get(cookie) 

    if(!session) {
        return {userID: null,  code: 'nosession'} // session not present in SESSIONS
    } 

    const expirationAt = session.expiresAt
    const userID = session.userID

    

    if (expirationAt < new Date(Date.now())) {
        SESSIONS.delete(cookie)
        return {userID: userID, code: 'expired'} // session has expired, delete it
    } else {
        return {userID: userID, code: 'notexpired'} // session has not expired
    }
    // True: Session has expired
    // False: Session is active
    // Undefined: Session never existed / Cookie not sent
    
}


// Setup all routes

app.get('/', (req, res) => {
    return res.send("Why are you reading my code? I'm a beginner okay?")
})

app.get('/profile', (req, res) => {
    const sessionStatus = hasExpired(req)
    if (sessionStatus.code == 'notexpired') {
        return res.send("Hey" + USERS.get(sessionStatus.userID).username)
    }
})

// Register route
app.post('/register', async (req, res) => {
    const {username, password} = req.body

    if (!username || !password) {
        return res.status(400).send("Username and Password are required!")
    }

    const isTaken = Array.from(USERS.values()).some((user) => {
        return user.username == username
    })
    
    if (isTaken) {
        return res.status(409).send("Username is already taken")
    } 

    const userID = USERS.size+1
    USERS.set(userID, {
        "username": username,
        "password": await bcrypt.hash(password, 10)
    })


    return setupIDs(res, userID).status(201).send("User has been registered")
})

// Login route
app.post('/login', async (req, res) => {

    const {username, password} = req.body
    let userID
    let user

    if (!username || !password) {
        return res.status(400).send("Username and Password are required!")
    }

    // const user = Array.from(USERS.values()).find(user => user.username == username)
    for (let [key, uzer] of USERS.entries()) {
        if (uzer.username == username) {
            user = uzer
            userID = key
            break;
        }
    }
    let oldSessions = []
    // Remove past sessions
    for (let [sessionid, info] of SESSIONS.entries()) {
        if (info.userID == userID) {
            oldSessions.push(sessionid)
        }
    }

    for (sessionid of oldSessions) {
        SESSIONS.delete(sessionid)
    }
    
    if (!user) {
        return res.status(404).send("User does not exist!")
    }

    const passwordMatch = await bcrypt.compare(password, user.password)

    if (!passwordMatch) {
        return res.status(401).send("Password is wrong!")
    }

    return setupIDs(res, userID).status(201).send("User has been logged in")

})

app.get('/logout', (req, res) => {
    const check = hasExpired(req)
    if (check.code == 'expired') {
        SESSIONS.delete(req.cookies.sessionID)
        return res.status(201).send("User has been logged-out")
    }
    return res.status(400).send("User is not logged-in in the first place")
})

app.use((req, res) => {
    res.send("Sorry diddy, this page does not exist!")
})



app.listen(process.env.PORT, ()=> {
    console.log("Server is running...")
    setInterval(()=> {
        for (const [sessionid, session] of SESSIONS) {
            const xpiresAt = session.expiresAt
            if (xpiresAt < new Date(Date.now())) {
                console.log(sessionid, session)
                SESSIONS.delete(sessionid)
            }
        }
    }, sessionExpiryCheckRate) 
})