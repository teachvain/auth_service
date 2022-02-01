const express = require("express");
const config = require("../../config.json");
const MEMBER = require("../../models/MEMBER");
var sanitize = require('mongo-sanitize');
const url = require("url");
const axios = require("axios")
const jwt = require("jsonwebtoken")


const route = express.Router();

route.get("/", async (req, res) => {
    //check if refresh_token is valid
    var refresh_token = req.cookies.refresh_token
    if (!refresh_token) return res.status(401).send({error: "missing refresh_token"})

    var memberdb = await MEMBER.findOne({"oauth.cookies.refresh_token": sanitize(refresh_token)});
    if (!memberdb) return res.status(401).send({error: "invalid refresh_token"})

    //decrypt access_token ans refresh_token
    const {createDecipheriv} = require('crypto');
    const decipher_access = createDecipheriv('aes256', config.eycryption_key, memberdb.oauth.e_iv);
    const decipher_refresh = createDecipheriv('aes256', config.eycryption_key, memberdb.oauth.e_iv);

    memberdb.oauth.access_token = decipher_access.update(memberdb.oauth.e_access_token, "hex", "utf-8") + decipher_access.final("utf-8")
    memberdb.oauth.refresh_token = decipher_refresh.update(memberdb.oauth.e_refresh_token, "hex", "utf-8") + decipher_refresh.final("utf-8")
    

    //check if user recived an api bann
    if (memberdb.oauth.blocking_state.is_blocked) return res.status(403).send({error: `You are being blocked from accessing our API. If you think that your API bann is unreasoned or unfair, contact a representative of Eat, Sleep, Nintendo, Repeat`})

    //check if discord_tokens are expired
    async function refresh_discord_access_token() {
        var formData = new url.URLSearchParams({
            client_id: config.discord_api.client_id,
            client_secret: config.discord_api.client_secret,
            grant_type: "refresh_token",
            refresh_token: refresh_token
        })
    
        const exchange_response = await axios.post("https://discord.com/api/oauth2/token",
                                        formData.toString(),
                                        {headers: {
                                            'Content-Type': 'application/x-www-form-urlencoded'
                                        }}).catch(async e => {
                                            return;
                                        })
    
        if (!exchange_response || !exchange_response.data || !exchange_response.data.access_token) return;

        //encrypt discord tokens
        const {createCipheriv, randomBytes} = require('crypto');
        const iv = randomBytes(16);
        const cipher_access = createCipheriv("aes256", config.eycryption_key, iv)
        const cipher_refresh = createCipheriv("aes256", config.eycryption_key, iv)

        //save new tokens to database
        await MEMBER.findOneAndUpdate({id: sanitize(memberdb.id)}, {
            "oauth.e_access_token": cipher_access.update(exchange_response.data.access_token, "utf-8", "hex") + cipher_access.final("hex"),
            "oauth.e_refresh_token": cipher_refresh.update(exchange_response.data.refresh_token, "utf-8", "hex") + cipher_refresh.final("hex"),
            "oauth.e_iv": iv,
        }, {new: true}).then(doc => {
            memberdb.oauth.refresh_token = exchange_response.data.refresh_token
            memberdb.oauth.access_token = exchange_response.data.access_token
        })
    }

    if (memberdb.oauth.expire_date < new Date()) await refresh_discord_access_token(memberdb);

    //try to fetch user data from discord
    fetchuserdatafromdiscord(false)
    async function fetchuserdatafromdiscord(retry) {
    await axios.get("https://discord.com/api/oauth2/@me", {headers: {"Authorization": `Bearer ${memberdb.oauth.access_token}`}}).then(async response => {
        //save data to database
        await MEMBER.findOneAndUpdate({id: response.data.user.id}, {
            informations: { name: response.data.user.username, discriminator: response.data.user.discriminator, avatar: response.data.user.avatar },
            "oauth.scopes": response.data.scopes,
            "oauth.expire_date": new Date(response.data.expires),
        })

        //check if database woud delete this member in 15 minutes
        var checkdate = new Date()
        checkdate.setMinutes(checkdate.getMinutes() + 16)
        if (memberdb.delete_in && checkdate > memberdb.delete_in) {
        //delay the delete_in counter by two hours 
        memberdb.delete_in.setHours(memberdb.delete_in.getHours() + 2)

        //save new delete_in to database
        await MEMBER.findOneAndUpdate({"id": response.data.user.id}, {"delete_in" : memberdb.delete_in})
        }
        
        //generate JSW and respond with token
        jwt.sign({id: response.data.user.id, username: response.data.user.username, discriminator: response.data.user.discriminator, avatar: response.data.user.avatar, type: memberdb.type, serverbooster: memberdb.serverbooster}, config.key, {expiresIn: "15m"}, function(err, token) {
        if (err) return res.status(500).send({error: "Something went wrong on our side while we tried to generate your JSW Token. Please try again later"})
        res.send({token: token})
        });
    
    }).catch(async (error) => {
        //something went wrong while fetching user data
        if (error.response) {
        //Discord respondet with an errorcode that is not in range of 2xx
        if (error.response.status == 401 && retry == false){
            await refresh_discord_access_token()
            fetchuserdatafromdiscord(true)
        }
        else return res.status(401).send({error: "We were not able to refresh the discord tokens that belonged to you"});
        }
        else if (error.request) {
        res.status(500).send({message: "something went wrong on our side. Please try again later"})
        }
    
    })
    
    }


    


    

})

module.exports = route;
