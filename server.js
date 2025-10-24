const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 5000;
const MONGO = process.env.MONGO_URI || 'mongodb://localhost:27017/multivendor';
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const STRIPE_SECRET = process.env.STRIPE_SECRET || 'sk_test_yourkey';
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173';

// Connect
mongoose.connect(MONGO, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('Mongo connect error', err.message));

// Models
const { Schema } = mongoose;
const userSchema = new Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['buyer','vendor','admin'], default: 'buyer' },
  emailVerified: { type: Boolean, default: false },
  verifyToken: String,
  resetToken: String,
  resetTokenExpiry: Date
}, { timestamps: true });
const productSchema = new Schema({
  title: String,
  description: String,
  price: Number,
  images: [String],
  vendor: { type: Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});
const orderSchema = new Schema({
  buyer: { type: Schema.Types.ObjectId, ref: 'User' },
  items: [{ product: { type: Schema.Types.ObjectId, ref: 'Product' }, qty: Number }],
  total: Number,
  status: { type: String, default: 'pending' } // pending, confirmed, shipped, delivered, cancelled
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Product = mongoose.model('Product', productSchema);
const Order = mongoose.model('Order', orderSchema);

// Auth helpers
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
function authMiddleware(req, res, next){
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  const token = auth.split(' ')[1];
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  } catch (err) { return res.status(401).json({ error: 'Invalid token' }); }
}
function adminOnly(req, res, next){
  if (!req.user) return res.status(401).json({ error: 'No user' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// Utilities
const crypto = require('crypto');
function randomToken(){ return crypto.randomBytes(32).toString('hex'); }

// Email setup (nodemailer)
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.mailtrap.io',
  port: process.env.SMTP_PORT || 587,
  auth: {
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || ''
  }
});

// Cloudinary setup
const cloudinary = require('cloudinary').v2;
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || '',
  api_key: process.env.CLOUDINARY_API_KEY || '',
  api_secret: process.env.CLOUDINARY_API_SECRET || ''
});
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });

// Routes
app.get('/', (req, res) => res.send('✅ Multivendor backend running (updated)'));

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const verifyToken = randomToken();
    const user = new User({ name, email, password: hashed, role, verifyToken });
    await user.save();
    // send verification email
    const url = `${CLIENT_URL}/verify-email?token=${verifyToken}&email=${encodeURIComponent(email)}`;
    await transporter.sendMail({
      from: process.env.EMAIL_FROM || 'no-reply@example.com',
      to: email,
      subject: 'Verify your email',
      text: `Click to verify: ${url}`,
      html: `<p>Click to verify: <a href="${url}">${url}</a></p>`
    });
    const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, email: user.email, name: user.name, role: user.role }});
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/verify-email', async (req, res) => {
  try {
    const { token, email } = req.query;
    const user = await User.findOne({ email, verifyToken: token });
    if (!user) return res.status(400).send('Invalid token');
    user.emailVerified = true; user.verifyToken = null;
    await user.save();
    res.send('Email verified — you can close this page and return to the app.');
  } catch (err) { res.status(500).send('Error'); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, email: user.email, name: user.name, role: user.role, emailVerified: user.emailVerified }});
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Password reset - request
app.post('/api/auth/request-reset', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.json({ ok: true }); // do not reveal
    const token = randomToken();
    user.resetToken = token;
    user.resetTokenExpiry = Date.now() + 1000 * 60 * 60; // 1 hour
    await user.save();
    const url = `${CLIENT_URL}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;
    await transporter.sendMail({
      from: process.env.EMAIL_FROM || 'no-reply@example.com',
      to: email,
      subject: 'Reset your password',
      text: `Reset: ${url}`,
      html: `<p>Reset: <a href="${url}">${url}</a></p>`
    });
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Password reset - complete
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, token, password } = req.body;
    const user = await User.findOne({ email, resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
    if (!user) return res.status(400).json({ error: 'Invalid token' });
    user.password = await bcrypt.hash(password, 10);
    user.resetToken = null; user.resetTokenExpiry = null;
    await user.save();
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Products - public read
app.get('/api/products', async (req, res) => {
  const products = await Product.find().populate('vendor','name email');
  res.json(products);
});

// Vendor creates product with image upload
app.post('/api/products', authMiddleware, upload.array('images', 6), async (req, res) => {
  try {
    if (req.user.role !== 'vendor' && req.user.role !== 'admin') return res.status(403).json({ error: 'Only vendors' });
    const { title, description, price } = req.body;
    const images = [];
    if (req.files && req.files.length) {
      for (const f of req.files) {
        const r = await cloudinary.uploader.upload_stream_async
          ? await new Promise((resolve, reject) => {
              const stream = cloudinary.uploader.upload_stream({ folder: 'multivendor' }, (err, result)=> err? reject(err): resolve(result));
              stream.end(f.buffer);
            })
          : await cloudinary.uploader.upload_stream({ folder: 'multivendor' }, (err, result)=> { /* fallback not implemented */ });
        images.push(r.secure_url || r.url);
      }
    }
    const p = new Product({ title, description, price, images, vendor: req.user.id });
    await p.save();
    res.json(p);
  } catch (err) { console.error(err); res.status(400).json({ error: err.message }); }
});

// Endpoint to upload single image (for clients that want URL)
app.post('/api/upload', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const r = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream({ folder: 'multivendor' }, (err, result)=> err? reject(err): resolve(result));
      stream.end(req.file.buffer);
    });
    res.json({ url: r.secure_url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Vendor edits product
app.put('/api/products/:id', authMiddleware, async (req, res) => {
  try {
    const p = await Product.findById(req.params.id);
    if (!p) return res.status(404).json({ error: 'Not found' });
    if (String(p.vendor) !== String(req.user.id) && req.user.role !== 'admin') return res.status(403).json({ error: 'Not allowed' });
    Object.assign(p, req.body);
    await p.save();
    res.json(p);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// Orders
app.post('/api/orders', authMiddleware, async (req, res) => {
  try {
    const { items } = req.body;
    let total = 0;
    for (const it of items) {
      const prod = await Product.findById(it.product);
      total += (prod.price || 0) * (it.qty || 1);
    }
    const order = new Order({ buyer: req.user.id, items, total, status: 'pending' });
    await order.save();
    res.json(order);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// Update order status (vendor or admin)
app.put('/api/orders/:id/status', authMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    const o = await Order.findById(req.params.id);
    if (!o) return res.status(404).json({ error: 'Not found' });
    // Basic check: vendor can only update if they own at least one product in order
    const isVendor = req.user.role === 'vendor';
    if (isVendor) {
      const products = await Product.find({ vendor: req.user.id }).select('_id');
      const vendorProductIds = products.map(p=>String(p._id));
      const touches = o.items.some(i => vendorProductIds.includes(String(i.product)));
      if (!touches) return res.status(403).json({ error: 'Cannot change order not related to you' });
    }
    // Accept status transitions; in production validate more strictly
    o.status = status;
    await o.save();
    res.json(o);
  } catch (err) { res.status(400).json({ error: err.message }); }
});

// Admin endpoints
app.get('/api/admin/users', authMiddleware, adminOnly, async (req, res) => {
  const users = await User.find().select('-password');
  res.json(users);
});
app.get('/api/admin/orders', authMiddleware, adminOnly, async (req, res) => {
  const orders = await Order.find().populate('buyer','name email').populate('items.product');
  res.json(orders);
});

// Stripe checkout session (creates a Checkout Session and returns URL)
const Stripe = require('stripe');
const stripe = new Stripe(STRIPE_SECRET, { apiVersion: '2022-11-15' });

app.post('/api/create-checkout-session', authMiddleware, async (req, res) => {
  try {
    const { items } = req.body; // items: [{ product, qty }]
    const line_items = [];
    for (const it of items) {
      const prod = await Product.findById(it.product);
      if (!prod) return res.status(400).json({ error: 'Product not found' });
      line_items.push({
        price_data: {
          currency: 'inr',
          product_data: { name: prod.title, description: prod.description || '' },
          unit_amount: Math.round((prod.price || 0) * 100)
        },
        quantity: it.qty || 1
      });
    }
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      line_items,
      success_url: CLIENT_URL + '/?checkout=success',
      cancel_url: CLIENT_URL + '/cart'
    });
    res.json({ url: session.url });
  } catch (err) { console.error(err); res.status(500).json({ error: err.message }); }
});

app.listen(PORT, () => console.log(`Server listening on ${PORT}`));

// Helper for cloudinary upload_stream promise (attach to cloudinary.uploader)
if (!cloudinary.uploader.upload_stream_async) {
  cloudinary.uploader.upload_stream_async = function(options) {
    return new Promise((resolve,reject)=>{
      const stream = cloudinary.uploader.upload_stream(options, (err,result)=> err? reject(err): resolve(result));
      return stream;
    });
  }
}
