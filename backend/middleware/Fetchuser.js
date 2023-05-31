// const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'Vishalisagood$boy';

const Fetchuser = (req, res, next) =>{

    //get the user from the jwt token and add id to req object
    const token = req.header('auth-token')
    if(!token){
        res.status(401).send({error: "please enter valid token"})
    }

    try {
        const data = jwt.verify(token, JWT_SECRET)
        req.user = data.user;

        next()
    } catch (error) {
        res.status(401).send({error: "please enter valid token"})
    }

}

module.exports = Fetchuser;