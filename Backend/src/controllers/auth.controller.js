const user = require("../models/user.model")
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');

async function registerusercontroller(req, res) {
    const {username, email, password} = req.body

    if (!username || !email || !password) {
        return res.status(400).json({message: "All fields are required"})
    }
    const existingUser = await user.findOne({$or: [{username}, {email}]})

    if (existingUser) {
        return res.status(400).json({message: "Username or email already exists"})
    }
    const hashedPassword = await bcrypt.hash(password, 10)
    const newUser = new user({
        username,
        email,
        password: hashedPassword
    })
    const token = jwt.sign({id: newUser._id}, process.env.JWT_SECRET, {expiresIn: '1d'})
    await newUser.save()
    res.cookie('token', token)
    res.status(201).json({message: "User registered successfully", id: newUser._id, username: newUser.username, email: newUser.email})
    

}


async function loginusercontroller(req, res) {
    const {email, password} = req.body

    const existingUser = await user.findOne({email})

    if (!existingUser) {
        return res.status(400).json({message: "Invalid email or password"})
    }

    const isMatch = await bcrypt.compare(password, existingUser.password)

    if (!isMatch) {
        return res.status(400).json({message: "Invalid email or password"})
    }

    const token = jwt.sign({id: existingUser._id}, process.env.JWT_SECRET, {expiresIn: '1d'})
    res.cookie('token', token)
    res.status(200).json({message: "User logged in successfully", id: existingUser._id, username: existingUser.username, email: existingUser.email})
}

async function logoutusercontroller(req, res) {
    res.clearCookie('token')
    res.status(200).json({message: "User logged out successfully"})
}

module.exports = { registerusercontroller, loginusercontroller, logoutusercontroller }