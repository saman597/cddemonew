const jwt = require('jsonwebtoken');
const crypto = require('crypto');
 
const User = require('../models/userModel');
const sendMail = require('../config/emailHandler');

const signToken = id => {

    return jwt.sign({ id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN
    });
};

const createJWT = (userId, statusCode, message, res) => {

    const token = signToken(userId);
    
    const cookieOptions = {
        expires: new Date(
          Date.now() + process.env.JWT_COOKIE_EXPIRY_DT * 24 * 60 * 60 * 1000
        ),
        secure: false,
        httpOnly: true
      };
        
    res.cookie('jwt', token, cookieOptions);
    
    res.status(statusCode).json({
        status: true,
        message
    });
};

exports.getData = async (req, res) => {
    try {

        const users = await User.find();

        res.status(200).json({ status: true, data: users });

    } catch (err) {
        console.log(err.message);
    }
};

exports.getDataById = async (req, res) => {
    try {

        if (!req.params.userId.match(/^[0-9a-fA-F]{24}$/)) {
            return res.status(400).json({ status: false, message: 'Invalid user ID.'});
        }

        const user = await User.findById(req.params.userId);

        if (!user) {
            return res.status(404).json({ status: false, message: 'Data not found.'}); 
        }

        res.status(200).json({ status: true, data: user });

    } catch (err) {
        console.log(err.message);
    }
};

exports.signUp = async (req, res) => {
    try {

        const { fullName, email, password } = req.body;

        if(!fullName || !email || !password ) {
            return res.status(400).json({ status: false, message: 'Invalid data.'});
        }
        
        const user= User({
            fullName,
            email,
            pass: password
        });
    
        await user.save();

        console.log(`Virtual pass = ${user.pass}`);

        createJWT(user._id, 201, "User signed up successfully.", res);
       
    } catch (err) {

        console.log(err.message);

        //handling duplicate key
        if ( err && err.code === 11000 ) {
            return res.status(409).json({ status: false, message: 'Duplicate data found.'});
        }
    }
};

exports.login = async (req, res) => {
    try {

        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ status: false, message: 'Credentials required.'}); 
        }

        var user;
        if (email) {
            user = await User.findOne({ email }).select('+password');    
        }

        if (!user || !( user.comparePassword(password, user.password))) {
            return res.status(401).json({ status: false, message: 'Incorrect credentials.'}); 
        } 

        createJWT(user._id, 200, 'User logged in successfully.', res);

    } catch (err) {
        console.log(err.message);
    }
};

exports.forgotPwd = async (req, res) => {
    try {

        const user = await User.findOne({email : req.body.email});

        const resetToken = crypto.randomBytes(32).toString('hex'); 

        const pwdResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        const linkExpireTime = Date.now() + 10 * 60 * 1000;

        if (!user) {
            return res.status(404).json({ status: false, message: 'No user found with this email address.'}); 
        }

        User.updateOne({email : req.body.email}, {$set : {pwdResetToken, linkExpireTime} }, (err, data)=> {

            if (err) {
                console.log(err);
            }

            const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword?rt=${resetToken}`;

            // Send Mail
            sendMail({ 
                from: `User <${process.env.SENDER_EMAIL}>`, 
                to: user.email, 
                subject: 'Password Reset Token',
                text: resetURL,
                html: "<h2>Valid for 10 minutes</h2>"
            });

            res.status(200).json({ status: true, link: resetURL });
        });    

    } catch (err) {
        console.log(err.message);
    }
};

exports.resetPwd =  async (req, res) => {
    try {
        const hashedToken = crypto.createHash('sha256').update(req.query.rt).digest('hex');
        const user = await User.findOne({
            pwdResetToken: hashedToken,
            linkExpireTime: { $gt: Date.now() }
        });
            
        if (user) {

            user.pass = req.body.password;
            user.pwdResetToken = undefined;
            user.linkExpireTime = undefined;

            await user.save();

            createJWT(user._id, 200, 'Password updated successfully.', res); 

        } else {
            res.status(400).json({status: false, message: 'Link expired.'});
        }

    } catch (err) {
        console.log(err.message);
    }
    
};
