const argon2 = require("argon2");

require ("dotenv").config();
const hashingOptions =  {
    type: argon2.argon2d,
    memoryCost: 2 ** 16,
    hashLength: 50,
};

const hashPassword = (req, res, next) => {
    argon2
      .hash(req.body.password, hashingOptions)
      .then((hashedPassword) => {
        console.log(hashedPassword);
  
        req.body.hashedPassword = hashedPassword;
        delete req.body.password;
  
        next();
      })
      .catch((err) => {
        console.error(err);
        res.sendStatus(500);
      });
  };
  const jwt = require('jsonwebtoken');
  const verifyPassword = (req, res) => {
    const { password } = req.body;
    const hashedPassword = req.user.hashedPassword;

    argon2 
        .verify(hashedPassword, password)
        .then ((match) => {
            if (match) {
                const payload = { sub: req.user.id };
        
                const token = jwt.sign(payload, process.env.JWT_SECRET, {
                  expiresIn: "1h",
                });
        
                delete req.user.hashedPassword;
                res.send({ token, user: req.user });
              } else {
                res.sendStatus(401);
              }
            })
        .catch((err) => {
            console.error(err);
            res.sendStatus(500);
          });
  }
  

  const verifyToken = (req, res, next) => {
    try {
        const authorization = req.get("Authorization");
        if (!authorization) {
            return res.status(401).send("Error: No authorization header");
          }
        const [type, token] = authorization.split(' ');
        if (type !== "Bearer") {
            return res.status(401).send("Error: Authorization header has incorrect type");
          }
          req.payload = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch(err) {
        console.log(err);
        res.sendStatus(401)
    }
  };

const verifyId = (req, res, next) => {
        const id = parseInt(req.params.id);

        const payloadUserId = req.payload ? req.payload.sub : null;
        

        if (!payloadUserId || id !== payloadUserId) {
          return res.status(403).send("Forbidden");
        }   
        next();
    }


module.exports = {
  hashPassword,
  verifyPassword,
  verifyToken,
  verifyId
};


