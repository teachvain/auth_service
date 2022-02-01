const mongoose = require("mongoose");

const Schema = mongoose.Schema({
  code: {type: String, required: true},

  method: {type: String, required: true},
  status: {
    name: {type: String, default: "started"},
    details: {type: String, default: "The Auth process has not yet begun. The user has only been redirected to Discord"},
    date: {type: Date, default: new Date()}
  },

  redirect: {type: String, required: true},

  client_data: {
    ip: String,
    user_auth: Object
  }
});

module.exports = mongoose.model("state_auth_code", Schema);
