require('dotenv').config();
const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(express.static(__dirname));

// MongoDB Mongoose Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/nexora';
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB Compass successfully.'))
  .catch(err => console.error('MongoDB connection error:', err));

// MongoDB Schemas
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String }, // Optional for social login users
  role: { type: String, required: true } // student or parent
});
const User = mongoose.model('User', UserSchema);

const TempUserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, required: true },
  otpCode: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 300 } // TTL Index: Expires in 5 minutes (300 seconds)
});
const TempUser = mongoose.model('TempUser', TempUserSchema);

// Nodemailer SMTP Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Helper to send OTP email
async function sendOTPEmail(email, name, otp) {
  const mailOptions = {
    from: `"Nexora AI" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: `Mã OTP Xác Nhận Tài Khoản Nexora của bạn: ${otp}`,
    html: `
      <div style="font-family: 'Be Vietnam Pro', sans-serif; max-width: 600px; margin: 0 auto; border: 3px solid #0F172A; border-radius: 16px; padding: 24px; background-color: #FAF9F5; box-shadow: 6px 6px 0px 0px #0F172A;">
        <h2 style="color: #0F172A; text-align: center; font-weight: 900; font-size: 28px;">Chào mừng ${name} đến với Nexora!</h2>
        <p style="font-size: 14px; font-weight: 500; color: #4B5563; text-align: center; margin-bottom: 24px;">Bạn đang thực hiện đăng ký tài khoản Nexora AI Learning OS. Dưới đây là mã OTP xác thực của bạn:</p>
        <div style="background-color: #FBBF24; border: 3px solid #0F172A; border-radius: 12px; padding: 16px; text-align: center; font-size: 32px; font-weight: 900; font-family: monospace; letter-spacing: 6px; box-shadow: 4px 4px 0px 0px #0F172A; margin: 0 auto 24px auto; width: fit-content; color: #0F172A;">
          ${otp}
        </div>
        <p style="font-size: 12px; color: #9CA3AF; text-align: center;">Mã xác thực này sẽ hết hạn sau 5 phút. Vui lòng không chia sẻ mã này với bất kỳ ai.</p>
      </div>
    `
  };
  return transporter.sendMail(mailOptions);
}

// -----------------------------------------------------------------
// AUTHENTICATION APIS
// -----------------------------------------------------------------

// API: Register - Generates and Emails OTP
app.post('/api/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) {
    return res.status(400).json({ error: 'Vui lòng cung cấp đầy đủ thông tin.' });
  }

  try {
    // Check if email already registered in permanent User collection
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: 'Email này đã được sử dụng.' });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // Upsert temporary user
    await TempUser.findOneAndDelete({ email: email.toLowerCase() });
    const tempUser = new TempUser({
      name,
      email: email.toLowerCase(),
      password,
      role,
      otpCode: otp
    });
    await tempUser.save();

    // Send the email
    await sendOTPEmail(email, name, otp);

    res.status(200).json({
      success: true,
      otpRequired: true,
      message: 'Mã OTP đã được gửi đến email của bạn.'
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Lỗi máy chủ trong quá trình gửi OTP.' });
  }
});

// API: Verify OTP and Register user in DB
app.post('/api/verify-otp', async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ error: 'Vui lòng cung cấp email và mã OTP.' });
  }

  try {
    const tempUser = await TempUser.findOne({ email: email.toLowerCase(), otpCode: otp });
    if (!tempUser) {
      return res.status(400).json({ error: 'Mã OTP không chính xác hoặc đã hết hạn.' });
    }

    // Move to permanent collection
    const newUser = new User({
      name: tempUser.name,
      email: tempUser.email,
      password: tempUser.password,
      role: tempUser.role
    });
    await newUser.save();

    // Remove from temporary collection
    await TempUser.findByIdAndDelete(tempUser._id);

    res.status(201).json({
      success: true,
      user: { name: newUser.name, email: newUser.email, role: newUser.role }
    });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'Lỗi máy chủ khi xác thực OTP.' });
  }
});

// API: Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Vui lòng điền đầy đủ email và mật khẩu.' });
  }

  try {
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Email hoặc mật khẩu không chính xác.' });
    }

    res.status(200).json({
      success: true,
      user: { name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Lỗi máy chủ khi đăng nhập.' });
  }
});

// API: Google OAuth Callback
app.post('/api/auth/google', async (req, res) => {
  const { credential } = req.body;
  if (!credential) {
    return res.status(400).json({ error: 'Token Google không hợp lệ.' });
  }

  try {
    // Call Google OAuth Tokeninfo API to verify and decode JWT
    const googleUrl = `https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`;
    const verifyRes = await fetch(googleUrl);
    const payload = await verifyRes.json();
    
    if (!verifyRes.ok || payload.error_description) {
      return res.status(401).json({ error: 'Không thể xác thực tài khoản Google.' });
    }

    const email = payload.email.toLowerCase();
    const name = payload.name;

    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(200).json({
        success: true,
        user: { name: user.name, email: user.email, role: user.role }
      });
    }

    // User is new, must prompt client to pick a role
    res.status(200).json({
      success: true,
      isNewSocialUser: true,
      socialUser: { name, email, provider: 'google' }
    });
  } catch (error) {
    console.error('Google OAuth error:', error);
    res.status(500).json({ error: 'Lỗi hệ thống khi xác thực Google.' });
  }
});

// API: Facebook OAuth Callback
app.post('/api/auth/facebook', async (req, res) => {
  const { accessToken } = req.body;
  if (!accessToken) {
    return res.status(400).json({ error: 'Access token Facebook không hợp lệ.' });
  }

  try {
    // Call Facebook Graph API to verify token and fetch profile
    const fbUrl = `https://graph.facebook.com/me?fields=name,email,picture&access_token=${accessToken}`;
    const verifyRes = await fetch(fbUrl);
    const payload = await verifyRes.json();
    
    if (!verifyRes.ok || payload.error) {
      return res.status(401).json({ error: 'Không thể xác thực tài khoản Facebook.' });
    }

    const email = payload.email ? payload.email.toLowerCase() : `${payload.id}@facebook.nexora.com`;
    const name = payload.name;

    // Check if user already exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(200).json({
        success: true,
        user: { name: user.name, email: user.email, role: user.role }
      });
    }

    // User is new, must prompt client to pick a role
    res.status(200).json({
      success: true,
      isNewSocialUser: true,
      socialUser: { name, email, provider: 'facebook' }
    });
  } catch (error) {
    console.error('Facebook OAuth error:', error);
    res.status(500).json({ error: 'Lỗi hệ thống khi xác thực Facebook.' });
  }
});

// API: Register Social User with Selected Role
app.post('/api/auth/social-register', async (req, res) => {
  const { name, email, role } = req.body;
  if (!name || !email || !role) {
    return res.status(400).json({ error: 'Thiếu thông tin đăng ký tài khoản.' });
  }

  try {
    // Upsert just in case they registered while completing role choice
    let user = await User.findOne({ email: email.toLowerCase() });
    if (user) {
      return res.status(200).json({
        success: true,
        user: { name: user.name, email: user.email, role: user.role }
      });
    }

    user = new User({
      name,
      email: email.toLowerCase(),
      role
    });
    await user.save();

    res.status(201).json({
      success: true,
      user: { name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error('Social registration error:', error);
    res.status(500).json({ error: 'Lỗi máy chủ khi hoàn tất đăng ký tài khoản liên kết.' });
  }
});

// API: Get client config credentials
app.get('/api/config', (req, res) => {
  res.json({
    googleClientId: process.env.GOOGLE_CLIENT_ID || '',
    facebookAppId: process.env.FACEBOOK_APP_ID || ''
  });
});

// Serve auth.html directly
app.get('/auth', (req, res) => {
  res.sendFile(path.join(__dirname, 'auth.html'));
});

// Fallback all other routing to index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Nexora server is running on http://localhost:${PORT}`);
});
