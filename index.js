const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');
const dotenv = require('dotenv');

dotenv.config(); // Load environment variables from .env file

const app = express();
const port = 8080;

app.use(bodyParser.json());

const JWT_SECRET = 'masai';
const dbName = 'users';

let db;

// Use process.env to access environment variables
const mongoURL = process.env.MONGO_URL;

MongoClient.connect(mongoURL, { useNewUrlParser: true, useUnifiedTopology: true }, (err, client) => {
  if (err) {
    console.error('Failed to connect to MongoDB:', err);
    return;
  }
  console.log('Connected to MongoDB');
  db = client.db(dbName);
});

function authenticateToken(req, res, next) {
  const token = req.header('Authorization');

  if (!token) return res.status(401).json({ message: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
}

app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    const usersCollection = db.collection('users');

    const existingUser = await usersCollection.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = { email, password: hashedPassword };
    await usersCollection.insertOne(newUser);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const usersCollection = db.collection('users');

    const user = await usersCollection.findOne({ email });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ email: user.email }, JWT_SECRET);

    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/employees', authenticateToken, async (req, res) => {
  try {
    const employee = req.body;

    const employeesCollection = db.collection('employees');

    await employeesCollection.insertOne(employee);

    res.status(201).json({ message: 'Employee created successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/employees', async (req, res) => {
  try {
    const employeesCollection = db.collection('employees');

    const page = parseInt(req.query.page) || 1;
    const pageSize = 5;
    const skip = (page - 1) * pageSize;

    const department = req.query.department;
    const filter = department ? { department } : {};

    const sortBySalary = req.query.sortBySalary === 'asc' ? 1 : -1;
    const sort = { salary: sortBySalary };

    const firstName = req.query.firstName;
    if (firstName) {
      filter.firstName = new RegExp(firstName, 'i'); // Case-insensitive search
    }

    const cursor = employeesCollection.find(filter).sort(sort).skip(skip).limit(pageSize);
    const employees = await cursor.toArray();

    res.json(employees);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.put('/employees/:id', authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const updatedEmployee = req.body;

    const employeesCollection = db.collection('employees');

    await employeesCollection.updateOne({ _id: ObjectId(id) }, { $set: updatedEmployee });

    res.json({ message: 'Employee updated successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.delete('/employees/:id', authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;

    const employeesCollection = db.collection('employees');

    await employeesCollection.deleteOne({ _id: ObjectId(id) });

    res.json({ message: 'Employee deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
