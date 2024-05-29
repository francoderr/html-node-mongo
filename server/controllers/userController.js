import UserModel from "../models/User.js";
import bcrypt from 'bcryptjs';

export const signUp = async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Check if the user already exists
        let user = await UserModel.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        // Create a new user
        user = new UserModel({
            username,
            email,
            password
        });

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        // Save the user to the database
        await user.save();

        // Respond with success message
        res.status(200).json({ msg: 'User created successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
}

export const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if the user exists
        let user = await UserModel.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        // Check the password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }

        // Respond with success message
        res.status(200).json({ msg: 'Login successful' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
}
