const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json()); // body-parser is not needed as of Express 4.16.0

// Middleware to check authentication
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Connect to MongoDB Atlas (no deprecated options)
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB Atlas'))
    .catch(err => console.error('MongoDB Atlas connection error:', err));

// Define Seller schema and model
const sellerSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const Seller = mongoose.model('Seller', sellerSchema);

// Define Product schema and model
const productSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
});

const Product = mongoose.model('Product', productSchema);

// API route to register a seller
app.post('/api/sellers/signup', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newSeller = new Seller({ username, password: hashedPassword });
        await newSeller.save();
        res.status(201).json({ message: 'Seller registered successfully' });
    } catch (err) {
        console.error('Failed to register seller:', err);
        res.status(500).json({ error: 'Failed to register seller' });
    }
});

// API route to login a seller
app.post('/api/sellers/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const seller = await Seller.findOne({ username });
        if (!seller) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const match = await bcrypt.compare(password, seller.password);
        if (!match) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: seller._id, username: seller.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        console.error('Failed to login seller:', err);
        res.status(500).json({ error: 'Failed to login seller' });
    }
});

// API route to fetch all products (public)
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (err) {
        console.error('Failed to fetch products:', err);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

// API route to add a product (authenticated users only)
app.post('/api/products', authenticateToken, async (req, res) => {
    const { name, description } = req.body;
    if (!name || !description) {
        return res.status(400).json({ error: 'Product name and description are required' });
    }

    try {
        const newProduct = new Product({ name, description });
        await newProduct.save();
        res.status(201).json({ message: 'Product added successfully', product: newProduct });
    } catch (err) {
        console.error('Failed to insert product:', err);
        res.status(500).json({ error: 'Failed to insert product' });
    }
});

// API route to update a product (authenticated users only)
app.put('/api/products/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    // console.log("Update Item  :",id);
    const { name, description } = req.body;
    if (!name || !description) {
        return res.status(400).json({ error: 'Product name and description are required' });
    }

    try {
        const updatedProduct = await Product.findByIdAndUpdate(id, { name, description }, { new: true });
        if (!updatedProduct) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json({ message: 'Product updated successfully', product: updatedProduct });
    } catch (err) {
        console.error('Failed to update product:', err);
        res.status(500).json({ error: 'Failed to update product' });
    }
});

// API route to delete a product (authenticated users only)
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    try {
        const deletedProduct = await Product.findByIdAndDelete(id);
        if (!deletedProduct) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json({ message: 'Product deleted successfully' });
    } catch (err) {
        console.error('Failed to delete product:', err);
        res.status(500).json({ error: 'Failed to delete product' });
    }
});

// app.listen(port, () => {
//     console.log(`Server running at http://localhost:${port}`);
// });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

