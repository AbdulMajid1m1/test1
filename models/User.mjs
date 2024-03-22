// User.js
import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema(
    {
        email: {
            type: String,
            required: [true, 'email is required'],
            unique: true
        },
        password: String, // not always required since user might register via OAuth
        username: {
            type: String,
            required: true,
            unique: false
        },
      
    },
    { timestamps: true }
);

export default mongoose.model("User", UserSchema);
