const Auth = require('../models2/auth2.js')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const register = async(req, res) => {
    try {
        
        const {username, email, password} = req.body
        const user = await Auth.findOne({email})

        if (user){
            return res.status(400).json({message: "Bu email hesabı zaten kullanımda!"})
        }

        if (password.length < 6){
            return res.status(400).json({message: "Parolanız 6 karakterden küçük olmamalıdır!"})
        }

        const passwordHash = await bcrypt.hash(password, 12)

        const newUser = await Auth.create({username, email, password: passwordHash})
    
        const userToken = jwt.sign({id: newUser.id}, process.env.SECRET_TOKEN, {expiresIn: '1h'});

        res.status(201).json({
            status: "OK",
            newUser,
            userToken
        })
        
    } catch (error) {
        return res.status(500).json({message: error.message})
    }
}

const login = async(req, res) => {
    try {

        const {email,password} = req.body;
        const user = await Auth.findOne({email});

        if(!user) {
            return res.status(400).json({message: "Böyle bir kullanıcı bulunamadı....."})
        }

        const comparePassword = await bcrypt.compare(password, user.password)
        
        if(!comparePassword) {
            return res.status(400).json({message: "Parolanız yanlış!"})
        }

        const token = jwt.sign({id: user.id}, process.env.SECRET_TOKEN, {expiresIn: '1h'} )

        res.status(200).json({
            status: "OK",
            user,
            token
        })

    } catch (error) {
        return res.status(500).json({message: error.message})
    }
}

const forgot = async (req, res) => {
    try {
      const {email} = req.body;
      const user = await Auth.findOne({email});
  
      if (!user) {
        return res.status(400).json({error: "Bu email adresiyle kayıtlı bir kullanıcı bulunmamaktadır."});
      }
  
     const resetToken =  jwt.sign({id: user.id}, process.env.SECRET_TOKEN, {expiresIn: '30m'});
  
     const sendPasswordResetEmail = async (email, resetToken) => {
      try {
        await firebase.auth().sendPasswordResetEmail(email, {
          url: `https://www.example.com/reset-password?token=${resetToken}`,
        });
      } catch (error) {
        console.error(error);
      }
    };

    res.status(200).json({message: "Şifre sıfırlama bağlantısı emailinize gönderilmiştir."});

    } catch (error) {
        return res.status(500).json({message: error.message});
    }
}

const reset = async (req, res) => {
  const { token, password } = req.body;

  jwt.verify(token, process.env.SECRET_TOKEN, async (error, decoded) => {
    if (error) {
      return res.status(400).send({ error: 'Token geçersiz veya süresi dolmuş.' });
    }

    const user = await User.findById(decoded.id);

    const hashedPassword = await bcrypt.hash(password, 12);

    user.password = hashedPassword;
    await user.save();

    res.status(200).send({ message: 'Şifreniz başarıyla sıfırlandı.' });
  });
};

const logout = async (req, res) => {
  res.status(200).json({message: "Başarıyla çıkış yapıldı."});
}

const deleteacc = async (req, res) => {
  try {
    console.log(req.body);

    const { email = "" } = req.body;

    const user = await Auth.findByIdAndDelete(email);

    res.status(200).json({ message: "Hesap başarıyla silindi." });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
};

const refresh = async (req, res) => {
  const { token } = req.body;

  jwt.verify(token, process.env.SECRET_TOKEN, async (error, decoded) => {
    if (error) {
      return res.status(400).send({ error: 'Token geçersiz veya süresi dolmuş.' });
    }

    const user = await User.findById(decoded.id);
  
    const newAccessToken = jwt.sign({ id: user._id }, process.env.SECRET_TOKEN, { expiresIn: '1h' });

    res.status(200).send({ newAccessToken });
  });
};


module.exports = {register, login, forgot, reset, logout, deleteacc, refresh}