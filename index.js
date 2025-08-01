require('dotenv').config();
console.log("🔍 MONGO_URL from env:", process.env.MONGO_URL);

var express= require('express');//importing
const bcrypt = require('bcrypt');
var cors = require('cors')
require('./connection.js');
//var empModel=require('./models/employee.js');//importing employee model
const userModel = require('./models/User.js');


const app=express();//initialize
const jwt = require('jsonwebtoken');
const SECRET_KEY = process.env.JWT_SECRET;

app.use(express.json());//middleware to parse JSON data
app.use(cors());//middleware to allow cross-origin requests

app.get('/', (req, res) => {//api creation
  res.send('Hello World')//we send a request and receive a response from backend as hello world
})

app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  const passwordTrollRules = [
  { check: pwd => /\d/.test(pwd), message: "Oops! Add a digit, like 1 or 7." },
  { check: pwd => /[A-Z]/.test(pwd), message: "Oops! Include at least one uppercase letter." },
  { check: pwd => /[!@#\$%\^&\*]/.test(pwd), message: "Add a spicy special character, like @ or #." },
  { check: pwd => pwd.includes("d"), message: "Where’s the third letter of 'Wednesday'? She’s waiting." },
  { check: pwd => pwd.includes("7"), message: "Include the number of continents." },
  { check: pwd => pwd.includes("O"), message: "O for Oxygen. And also for 'Oh no, you forgot it'." },
  { check: pwd => pwd.includes("B") && pwd.includes("C"), message: "Password must include initials of 1999 US Presidents.CAPS" },
  { check: pwd => pwd.includes("506"), message: "What’s 2024 ÷ 4? That’s right. Include that magic number." },
  { check: pwd => {
      const symbols = (pwd.match(/[!@#$%^&*()]/g) || []);
      const unique = [...new Set(symbols)];
      return unique.length >= 2;
    }, message: "Two different symbols please. Diversity matters—even in symbols." },
  { check: pwd => pwd.includes("8"), message: "Don’t forget π’s 11th decimal digit. Math trauma unlocked." },
  { check: pwd => (pwd.match(/a/gi) || []).length >= 5, message: "We demand at least 5 a’s. It’s the law now." },
  { check: pwd => pwd.includes("Tue"), message: "The day after Monday? Yep, we want that abbreviation(Start in caps)." },
  { check: pwd => pwd.includes("Scar"), message: "Add the Lion King villain. Long live the king 👑(Start in caps)." },
];

  try {
    const existingUser = await userModel.findOne({ email });
    if (existingUser) {
      return res.status(400).send("User already exists");
    }

    const unmetRules = passwordTrollRules.filter(rule => !rule.check(password));

    if (unmetRules.length > 0) {
      const randomRule = unmetRules[Math.floor(Math.random() * unmetRules.length)];
      return res.status(400).send(randomRule.message);
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new userModel({ name, email, password: hashedPassword });
    await newUser.save();

    return res.status(200).send("User registered successfully 🎉 (after a battle of wills)");
  } catch (err) {
    console.error(err);
    return res.status(500).send("Server error. Probably emotional damage.");
  }
});


app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user exists
    const user = await userModel.findOne({ email });
    if (!user) {
      return res.status(400).send("User not found");
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send("Invalid password");
    }

    // Create JWT token (only includes user ID)
    const payload = { id: user._id };
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });

    // Send response (no role included)
    res.status(200).send({ message: "Login successful", token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).send("Server error");
  }
});







app.get('/trial',(req,res)=>{
  res.send("This is a trial message")
})



app.listen(process.env.PORT || 3000,()=>
{
   console.log("Port 3000 is connected")
})

