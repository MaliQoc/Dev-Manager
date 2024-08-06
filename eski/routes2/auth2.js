const express = require('express')
const {register, login, forgot, reset, logout, deleteacc, refresh} = require('../controllers2/auth2.js')

const router = express.Router()

//post , get , update , delete
router.post('/register', register)
router.post('/login', login)
router.post('/forgot', forgot)
router.post('/reset', reset)
router.post('/logout',logout)
router.post('/deleteacc',deleteacc)
router.post('/refresh',refresh)

module.exports = router