const express = require('express');
const {tokenVerify, register, login, forgotPassword, resetPassword, logout, deleteAccount, refreshToken,} = require('../controllers4/auth4.js');

const router = express.Router();

router.get('/tokenverify', tokenVerify);
router.post('/login', login);
router.post('/register',register);
router.post('/forgotpassword', forgotPassword);
router.post('/resetpassword', resetPassword);
router.post('/logout', logout);
router.delete('/deleteaccount', deleteAccount);
router.post('/refreshtoken', refreshToken);
router.get('/userinfo', getUserInfo); // New route
module.exports = router;
