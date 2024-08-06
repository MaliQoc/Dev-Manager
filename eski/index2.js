const express = require('express')
const cors = require('cors')
const dotenv = require('dotenv')
const db = require('./config2/database2.js')
const Auth = require('./routes2/auth2.js')

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({limit: '30mb', extended: true}))
app.use(express.urlencoded({limit: '30mb', extended: true}))

app.use('/', Auth)

const PORT = 8080;

db()

app.listen(PORT, () => {
    console.log("server is running on port: 8080");
})