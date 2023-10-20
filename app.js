const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const cors = require('cors'); 

app.use(bodyParser.json());
app.use(cors()); 

const placesRoutes = require('./routes/places');
const usersRoutes = require('./routes/users');
 
app.get('/', (req, res) => {
  res.json({ message: 'API di esempio su Vercel!' });
});  

app.use('/api', placesRoutes);

app.use('/users', usersRoutes); 

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

