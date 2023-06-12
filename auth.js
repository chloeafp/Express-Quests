const argon2 = require("argon2");

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

  const verifyPassword = (req, res) => {
    const { password } = req.body;
    const hashedPassword = req.user.hashedPassword;

    argon2 
        .verify(hashedPassword, password)
        .then ((match) => {
            if (match) {
                res.send("Credentials are valid");}
            else {
                res.sendStatus(401);
            }
        })
        .catch((err) => {
            console.error(err);
            res.sendStatus(500);
          });
  }
  

module.exports = {
  hashPassword,
  verifyPassword
};


