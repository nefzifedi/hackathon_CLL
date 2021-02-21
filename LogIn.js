var express = require("express");
var app = express();
var cors = require("cors");
var bodyParser = require("body-parser");
const { request, get } = require("http");
const { urlencoded } = require("body-parser");
var mysql = require("mysql");
const { error, table, Console } = require("console");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");
// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));

// parse application/json
app.use(bodyParser.json());

//var Buffer = require("buffer/").Buffer;

var con = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
});
con.connect(function (err) {
  if (err) throw err;
  var sql = "use HackthonCLL";
  con.query(sql, function (err, result) {
    if (err) throw err;
  });
});
const Key_secret = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
function generateAccessToken(id) {
  return jwt.sign({ id }, Key_secret, { expiresIn: 15 });
}
function parseJwt(Token) {
  let base64Url = Token.split(".")[1]; // token you get
  let base64 = base64Url.replace("-", "+").replace("_", "/");
  let decodedData = JSON.parse(
    Buffer.from(base64, "base64").toString("binary")
  );
  return decodedData;
}
function authenticateToken(req, res, next) {
  // Gather the jwt access token from the request header
  const authHeader = req.headers.authorization;
  if (authHeader != []) {
    jwt.verify(authHeader, Key_secret, (err, user) => {
      if (err) {
        console.log(err);
        return res.sendStatus(300);
      } else {
        req.user = user;
        next();
      }
      // pass the execution off to whatever request the client intended
    });
  } else {
    return res.sendStatus(401); // if there isn't any token
  }
}

function AddUser(Nom, MotPasse, Role) {
  var x = new Promise(async function (resolve, reject) {
    bcrypt.genSalt(saltRounds, (err, salt) => {
      bcrypt.hash(MotPasse, salt, (err, hash) => {
        var sql = `insert into Member (NomUser,MotDePasse,Role) values ("${Nom}","${hash}","${Role}")`;
        con.query(sql, function (err, result) {
          if (err) return reject(err);
          resolve(result.insertId);
        });
      });
    });
  });
  return x;
}
//Recherche l exixtance dans le table login
function RecherExist(Nom) {
  let x = new Promise(function (resolve, reject) {
    var sql = `select * from Member where MEMBER.NomUser="${Nom}"`;
    con.query(sql, function (err, result) {
      if (err) return reject(err);
      resolve(result);
    });
  });
  return x;
}

//Comparaison Mot de passe
function hash(PasseUser, PasseBD) {
  let x = new Promise(function (resolve, reject) {
    bcrypt.compare(PasseUser, PasseBD, async function (err, results) {
      if (err) return reject(err);
      resolve(results);
    });
  });
  return x;
}
function Supprimer(id) {
  let x = new Promise(function (resolve, reject) {
    var sql = `DELETE FROM Member Member.id = "${id}"`;
    con.query(sql, function (err, result) {
      if (err) return reject(err);
      resolve(result);
    });
  });
}
app.use(cors());
app.use("/", express.static("public"));

app.get("/", async function (req, res) {
  const authHeader = req.headers.authorization;
  if (authHeader != []) {
    jwt.verify(authHeader, Key_secret, (err, user) => {
      if (err) {
        console.error(err);
        return res.sendStatus(401);
      } else {
        req.user = user;
        return res.sendStatus(200);
      }
      // pass the execution off to whatever request the client intended
    });
  } else {
    return res.sendStatus(401); // if there isn't any token
  }
});
app.post("/LogIn", async function (req, res) {
  try {
    let x = await RecherExist(req.body.AddGmail);
    let b = null;
    if (x.length != 0) {
      let b = await hash(req.body.MotPasse, x[0].MotPasse);
      if (b) {
        const accessToken = generateAccessToken([x[0].id, x[0].Nom]);
        return res.status(200).json({
          AccessToken: accessToken,
          Compte: [x[0].Nom, x[0].Role],
        });
      }
    } else {
      res.status(403).json({ AccessToken: false });
    }
  } catch (err) {
    console.log(err);
    return res.status(500).json({ success: false });
  }
});

app.post("/Inscrit", async function (req, res) {
  try {
    let x = await RecherExist(req.body.Nom);
    if (x.length === 0) {
      AddUser(req.body.Nom, req.body.MotPasse, req.body.Role);
      return res.status(200).json({ success: true });
    } else {
      return res.status(200).json({ success: false });
    }
  } catch (err) {
    console.log(err);
    return res.status(500).json({ success: false });
  }
});
app.use("/sign", express.static("public/signUP.html"));

app.post("/SignUp", async function (req, res) {
  //1-Recherche:
  try {
    var x = await CountExist(req.body.Nom);
  } catch (err) {
    console.log(err.sql);
    return res.status(500).json({ success: false });
  }
  if (x == 0) {
    console.log("this count is exist");
    return res.status(500).json({ success: false });
  }
  //2-Hashge the password/Storage :
  else {
    var y = await AddUser(req.body.Nom, req.body.pass);
  }
  res.cookie("id", y);
  return res.status(200).json({ success: true, user: y });
});

app.listen(8080);
