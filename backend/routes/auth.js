const express = require("express");
const User = require("../models/User");
const router = express.Router();
const { body, validationResult } = require("express-validator");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Fetchuser = require("../middleware/Fetchuser");

const JWT_SECRET = 'Vishalisagood$boy';


//Route 1: Create a user using: POST "/api/auth/createuser" no login required
router.post("/createuser", [

    body('name', 'Enter a valid name').isLength({ min: 3 }),
    body('email', 'Enter a valid email').isEmail(),
    body('password', 'password is too short').isLength({ min: 4 }),

], async (req, res) => {
    
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({ erros: errors.array() });
    }

    try {

        let user = await User.findOne({ email: req.body.email });
        if(user){
            return res.status(400).json({error: "sorry user exists"})
        }

        const salt = await bcrypt.genSalt(10);
        const secPass = await bcrypt.hash(req.body.password, salt);

        user = await User.create({
            name: req.body.name,
            email: req.body.email,
            password: secPass,
        })

        const data = {
            user:{
                id: user.id,
            }
        }
        const authtoken = jwt.sign(data, JWT_SECRET);

        res.json({authtoken})

    } catch (error) {
        console.error(error.message);
        res.status(500).send("some error occured")
    }
})


//Route 2: Aouthenticate a user using: POST "/api/auth/login" no login required
router.post("/login", [

    body('email', 'Enter a valid email').isEmail(),
    body('password', 'Cannot be blank').exists(),

], async (req, res) => {

    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return res.status(400).json({ erros: errors.array() });
    }

    const {email, password} = req.body;
    try {

        let user = await User.findOne({email});
        if(!user){
            return res.status(400).json({ error: "please login with correct credentials"});

        }
        const passwordCompare = await bcrypt.compare(password, user.password);
        if(!passwordCompare){
            return res.status(400).json({ error: "please login with correct credentials"});
        }
        const data ={
            user:{
                id: user.id,
            }
        }
        const authtoken = jwt.sign(data, JWT_SECRET);

        res.json({authtoken})
        
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal server error")
    }


})


//Route 2: get logged in user details: POST "/api/auth/getuser" login required
router.post("/getuser", Fetchuser, async (req, res) => {

    try {
        const userId = req.user.id;
        const user = await User.findById(userId).select("-password")
        res.send(user)
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal server error")
    }
    
})



module.exports = router;