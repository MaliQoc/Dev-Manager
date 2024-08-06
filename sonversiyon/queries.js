const checkEmailExists = 'SELECT * FROM users WHERE email = $1';
const updateUser = 'UPDATE users SET password = $1 WHERE email = $2';
const removeUser = 'DELETE FROM users WHERE email = $1';

module.exports = {checkEmailExists, updateUser, removeUser};