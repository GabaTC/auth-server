import express, { response } from "express";
import mysql from "mysql";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt, { hash } from "bcrypt";
import cookieParser from "cookie-parser";
const salt = 10;

const app = express();
app.use(express.json());
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["POST", "GET"],
    credentials: true
}));
app.use(cookieParser());

const db = mysql.createPool({
  connectionLimit: 100,
  host: "localhost",
  user: "root",
  password: "",
  database: "signup",
});

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if(!token){
    return res.json({ Error: "You are not auth" });
  } else {
    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
      if(err){
        return res.json({ Error: "Invalid token" });
      } else {
        req.name = decoded.name;
        next();
      }
    })
  }
}

app.get('/', verifyUser, (req,res) => {
  return res.json({Status: "Success", name: req.name});
})

app.post("/register", (req, res) => {
  console.log("hola", JSON.stringify(req.body));
  const sql = "INSERT INTO login (`name`,`email`,`password`) VALUES (?)";
  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err)
      return res.status(500).send({ Error: "Error for hassing password" });
    const values = [req.body.name, req.body.email, hash];
    db.query(sql, [values], (e, result) => {
      console.log(JSON.stringify(e));
      console.log(JSON.stringify(result));
      if (e)
        return res
          .status(500)
          .send({ Error: "Inserting data Error in server" });
      else return res.json({ Status: "Success" });
    });
  });
});

app.post("/login", (req, res) => {
  const sql = "SELECT * FROM login WHERE email = ?";
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.status(500).send({ Error: "Login error in server" });
    if (data.length > 0) {
      bcrypt.compare(
        req.body.password.toString(),
        data[0].password,
        (e, response) => {
          if (e) return res.status(500).send({ Error: "Password error" });
          if (response) {
            const name = data [0].name;
            const token = jwt.sign({name}, "jwt-secret-key", {expiresIn: '1d'});
            res.cookie('token', token);
            return res.json({ Status: "Success" });
          } else {
            return res.json({ Error: "No password" });
          }
        }
      );
    } else {
      return res.status(500).send({ Error: "No email" });
    }
  });
});

app.get('/logout', (req,res) => {
  res.clearCookie('token');
  return res.json({Status: "Success"});
})

app.listen(8081, () => {
  console.log("Running. ..");
});
