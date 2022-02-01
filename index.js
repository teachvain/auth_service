const express = require("express");
var bodyParser = require('body-parser')
var cookieParser = require("cookie-parser");


const app = express();
app.use(cookieParser());
app.use(bodyParser.json())

//database
require("./database")

//import routes
app.use("/", require("./routes/index"))

app.listen(6679, () => {
    console.log("AUTH_SERVICE is active and listenig on 6679");
})