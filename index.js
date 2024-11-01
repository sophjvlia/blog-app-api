const path = require('path');
const express = require('express');
const cors = require('cors');
const pg = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const app = express();
const port = 3010;
const { Pool } = pg;
const pool = new Pool({
  connectionString: process.env.POSTGRES_URL,
});

app.use(cors());
app.use(express.json());

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  try {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const result = await pool.query(
      'INSERT INTO blog_users (email, password) VALUES ($1, $2) RETURNING id, email',
      [email, hashedPassword]
    );
    const user = result.rows[0];

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({ token, user: { id: user.id, email: user.email } });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ error: 'Registration failed', details: error.message });
  }
});

// app.get('/blogs', async (req, res) => {

//   try {
//     const result = await pool.query('SELECT * FROM blogs');

//     res.status(200).json(result.rows);
//   } catch (err) {
//     console.error('Error executing query', err);
//     res.status(500).json({ error: 'Database query failed' });
//   }
// });

// app.get('/blogs/:id', async (req, res) => {
//   const blogId = parseInt(req.params.id);

//   try {
//     const result = await pool.query('SELECT * FROM blogs WHERE id = $1'. [blogId]);

//     if (result.rows.length === 0) {
//       res.status(400).json({ error: 'Blog post not found' });
//     }

//     res.status(200).json(result.rows[0]);
//   } catch (err) {
//     console.error('Error executing query', err);
//     res.status(500).json({ error: 'Database query failed' });
//   }
// });

// app.post('/blogs', (req, res) => {
//   const { title, description, user_id } = req.body;

//   try {
//     const result = await pool.query(
//       'INSERT INTO blogs (user_id, title, description) VALUES ($1, $2, $3) RETURNING *',
//       [user_id, title, description]
//     );

//     res.status(200).json({ message: 'Blog post added successfully', blog: result.rows[0] });
//   } catch (err) {
//     console.error('Error executing query', err);
//     res.status(500).json({ error: 'Database query failed' });
//   }
// });

// app.patch('/blogs/:id', (req, res) => {
//   const blogId = parseInt(req.params.id);
//   const { title, description, user_id } = req.body;

//   try {
//     const result = await pool.query(
//       'INSERT INTO blogs (user_id, title, description) VALUES ($1, $2, $3) RETURNING *',
//       [user_id, title, description]
//     );

//     res.status(200).json({ message: 'Blog post updated successfully', blog: result.rows[0] });
//   } catch (err) {
//     console.error('Error executing query', err);
//     res.status(500).json({ error: 'Database query failed' });
//   }
// });

app.get('/', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'pages/index.html'));
});

// app.listen(port, () => {
//   console.log(`Example app listening at http://localhost:${port}`);
// });

module.exports = app;
