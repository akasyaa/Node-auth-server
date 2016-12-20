const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

const userSchema = new Schema({
    email: { type: String, unique: true, lowercase: true },
    password: String
});

// Before saving a model, run this function
userSchema.pre('save', function(next) {
    // Get access to the user model
    const user = this;

    // Generate a salt, then run callback
    bcrypt.genSalt(10, function(err, salt) {
        if (err) {
            return next(err);
        }

        // Hash password using salt, then run callback
        bcrypt.hash(user.password, salt, null, function(err, hash) {
            if (err) {
                return next(err);
            }

            // Overwrite plain text password with encrypted password
            user.password = hash;
            next();
        })
    });
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if (err) {
            return callback(err);
        }

        callback(null, isMatch);
    });
}

const model = mongoose.model('user', userSchema);

module.exports = model;
