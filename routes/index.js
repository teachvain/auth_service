const express = require("express");

const routes = express.Router();

routes.use("/discord", require("./auth/discord_oauth"))
routes.use("/accesstoken", require("./auth/generate_access_token"))
routes.use("/revocation", require("./auth/revoke_discord_access"))

module.exports = routes;
