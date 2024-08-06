const express = require('express');
const userRoutes = require('./routes4/auth4.js');

const app = express();
const PORT = 3000;
app.use(express.json());

app.use("/api/v1/users", userRoutes);

app.listen(PORT, () => console.log('app listening on port ${port}'));