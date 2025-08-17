const express = require('express');
const { json } = express;
const cors = require('cors');
const uploadRoutes = require('./routes/upload.js');

const app = express();
app.use(cors({origin: 'http://localhost:4200'  // your Angular app origin
}));
app.use(json({ limit: '50mb' })); 
app.use('/api', uploadRoutes);
app.listen(3000, () => console.log('Server running on port 3000'));
