const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../config4/database4.js');
const queries = require('../queries.js');

const SALT_ROUNDS = 10;
const ACCESS_TOKEN_EXPIRES_IN = '15m';
const REFRESH_TOKEN_EXPIRES_IN = '7d';

getTokenFromHeaders = async (headers) => {
  const authHeader = headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }
  return null;
};

checkExpired = async (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return { verified: true, email: decoded.userId };
  } catch (error) {
    return { verified: false, message: error.message };
  }
};

tokenVerify = async (req, res) => {
  try {
    const token = getTokenFromHeaders(req.headers);
    if (token === null) return res.status(401).json({ message: 'Token bulunamadı.' });
    const result = await checkExpired(token);
    if (result.verified) return res.status(200).json({ email: result.email });
    return res.status(401).json({ message: result.message });
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error_message: error.message });
  }
};

//ALTER TABLE users
// ADD COLUMN name VARCHAR(100);

register = async (req, res) => {
  try {
      const existingUser = await pool.query(queries.checkEmailExists, [req.body.email]);
      if (existingUser.rows.length > 0) {
          console.error('Bu email adresi zaten kullanımda.');
          return res.status(200).json({ "code": 400, "message": "Bu email adresi zaten kullanımda." });
      }
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      const accessToken = jwt.sign({ userId: req.body.email }, process.env.JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });
      const refreshToken = jwt.sign({ userId: req.body.email }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRES_IN });
      const query = `INSERT INTO users (name, email, password, access_token, refresh_token) 
      VALUES ($1, $2, $3, $4, $5) 
      RETURNING id, name, email, access_token, refresh_token`;
      const values = [req.body.name, req.body.email, hashedPassword, accessToken, refreshToken];
      const result = await pool.query(query, values);
      const user = result.rows[0];
      console.table(result.rows);
      return res.status(200).json({ "code": 200, "data": user });
  } catch (error) {
      console.error('Kişi eklenirken bir hata oluştu:', error.stack);
      return res.status(400).json({ "code": 400, "message": error.message });
  }
};
login = async (req, res) => {
  try {
    const user = await pool.query(queries.checkEmailExists, [req.body.email]);
    if (user.rows.length === 0) return res.status(400).json({ message: 'Kullanıcı bulunamadı.'});
    const isPasswordValid = await bcrypt.compare(req.body.password, user.rows[0].password);
    if (!isPasswordValid) return res.status(401).json({ message: 'Hatalı şifre.' });
    const accessToken = jwt.sign({ userId: user.rows[0].email }, process.env.JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });
    const refreshToken = jwt.sign({ userId: user.rows[0].email }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRES_IN });
    return res.status(200).json({ accessToken, refreshToken });
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error_message: error.message });
  }
};

forgotPassword = async (req, res) => {
  try {
    const user = await pool.query(queries.checkEmailExists, [req.body.email]);
    if (user.rows.length === 0) return res.status(400).json({ message: 'Kullanıcı bulunamadı.'});
    return res.status(200).json({ message: 'Şifre sıfırlama talimatları e-postanıza gönderildi.'});
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error_message: error.message });
  }
};

resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;
    const decoded = jwt.verify(token, process.env.RESET_PASSWORD_TOKEN_SECRET);
    const user = await pool.query(queries.checkEmailExists, [decoded.userId]);
    if (user.rows.length === 0) return res.status(400).json({ message: 'Kullanıcı bulunamadı.'});
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    await pool.query(queries.updateUser, [hashedPassword, decoded.userId]);
    return res.status(200).json({ message: 'Şifreniz başarıyla sıfırlandı.'});
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error_message: error.message });
  }
};

logout = async (req, res) => {
  try {
    const token = getTokenFromHeaders(req.headers);
    if (token === null) return res.status(401).json({ message: 'Token bulunamadı.'});
    return res.status(200).json({ message: 'Başarıyla çıkış yapıldı.'});
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error_message: error.message });
  }
};

deleteAccount = async (req, res) => {
  try {
    const token = getTokenFromHeaders(req.headers);
    if (token === null) return res.status(401).json({ message: 'Token bulunamadı.'});
    const result = await checkExpired(token);
    if (!result.verified) return res.status(401).json({ message: 'Token süresi doldu.'});
    await pool.query(queries.removeUser, [result.email]);
    return res.status(200).json({ message: 'Hesabınız başarıyla silindi.'});
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error_message: error.message });
  }
};

refreshToken = async (req, res) => {
  try {
    const token = req.body.refreshToken;
    if (token === null) return res.status(401).json({ message: 'Token bulunamadı.'});
    const result = await checkExpired(token, REFRESH_TOKEN_SECRET);
    if (!result.verified) return res.status(401).json({ message: 'Token süresi doldu.'});
    const accessToken = jwt.sign({ userId: result.email }, process.env.JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });
    return res.status(200).json({ accessToken });
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error_message: error.message });
  }
};

const getUserInfo = async (req, res) => {
  try {
    const token = getTokenFromHeaders(req.headers);
    if (token === null) return res.status(401).json({ message: 'Token bulunamadı.' });
    const result = await checkExpired(token);
    if (!result.verified) return res.status(401).json({ message: 'Token süresi doldu.' });
    const userInfo = await pool.query(queries.getUserInfo, [result.email]); 
    if (userInfo.rows.length === 0) return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
    const user = userInfo.rows[0];
    // Return the user information
    return res.status(200).json({ user });
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error_message: error.message });
  }
};

module.exports = { tokenVerify, register, login, forgotPassword, resetPassword, logout, deleteAccount, refreshToken , getUserInfo };
