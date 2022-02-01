const mongoose = require("mongoose");

const MemberSchema = mongoose.Schema({
  id: { required: true, type: String },
  informations: { name: String, discriminator: String, avatar: String },
  type: { default: 0, type: Number },

  oauth: {
    e_access_token: { default: null, type: String },
    e_refresh_token: String,
    e_iv: Buffer,
    expire_date: Date,
    scopes: Array,
    cookies: Array,
    blocking_state: {
      is_blocked: { type: Boolean, default: false },
      date: Date,
      reason: String,
    },
  },

  delete_in: { default: null, type: Date },
  joined: { default: new Date(), type: Date },
});

module.exports = mongoose.model("Member-v2.0", MemberSchema);
