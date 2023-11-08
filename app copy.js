const express = require('express');
const session = require('express-session');
const app = express();
const bodyParser = require('body-parser');
const cors = require('cors'); 
const passport = require('passport');

app.use(bodyParser.json());
app.use(cors()); 

app.use(session({
  secret: 'viewster_aaron_manu',
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

const usersRoutes = require('./routes/users');
 
app.get('/', (req, res) => {
  res.json({ message: 'API di esempio su Vercel!' });
});  

//app.use('/api', placesRoutes);
 
app.use('/users', usersRoutes); 

const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

