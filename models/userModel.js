const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

const schemaOptions = {
  timestamps: true,  
  toJSON: {
    virtuals: true
  },
  toObject: {
    virtuals: true
  }
};

const userSchema = new mongoose.Schema(
  {
    fullName : {
        type: String,
        required: [true, 'Full name is required.']  
    },
    email : {
        type: String,
        trim: true,
        lowercase: true, 
        unique: true,
        required: [true, 'Email address is required.'],
        validate: [validator.isEmail, 'Please provide a valid email address.']
    },
    password : {
        type: String,
        trim: true,
        required: [true, 'Password is required.'],
        maxlength: 128, 
        minlength: 6,
        select: false
    },
    pwdResetToken : {
      type: String
    },
    linkExpireTime : {
      type: Date
    }
  },
  { id: false },
  schemaOptions
);

userSchema.virtual('pass')
.set(function(pass){
  this._pass = pass;
  this.password = bcrypt.hashSync(pass, 8);
});

userSchema.methods.comparePassword =  function( reqPassword, userPassword ) {
    let res = bcrypt.compareSync(reqPassword, userPassword);
    return res;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
