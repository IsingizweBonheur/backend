const express = require('express');
const cors = require('cors');
const { createClient } = require("@supabase/supabase-js");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
require("dotenv").config();
const app = express();

app.use(cors({
  origin: [
    'http://localhost:3000', 
    'http://127.0.0.1:3000', 
    'https://quickfastfood.vercel.app'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'user-id', 'user-email']
}));
app.use(express.json());

// For Render deployment, use local uploads directory
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024,
  }
});

// Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
  console.error('Missing Supabase environment variables');
  process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseServiceKey);

// Serve static files from uploads directory
app.use('/uploads', express.static(uploadsDir));

// In-memory store for password reset tokens
const passwordResetTokens = new Map();

const cleanupExpiredTokens = () => {
  const now = new Date();
  for (const [token, data] of passwordResetTokens.entries()) {
    if (now > data.expiresAt) {
      passwordResetTokens.delete(token);
    }
  }
};

setInterval(cleanupExpiredTokens, 60 * 60 * 1000);

// User Registration Endpoint
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    // Check if user already exists
    const { data: existingUser, error: checkError } = await supabase
      .from("users")
      .select("id")
      .or(`email.eq.${email},username.eq.${username}`)
      .single();

    if (existingUser) {
      return res.status(400).json({ message: "User already exists with this email or username" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const { data: user, error: createError } = await supabase
      .from("users")
      .insert([
        {
          username,
          email,
          password: hashedPassword,
        }
      ])
      .select()
      .single();

    if (createError) {
      console.error("User creation error:", createError);
      return res.status(500).json({ message: "Failed to create user" });
    }

    // Remove password from response
    const { password: _, ...userWithoutPassword } = user;

    res.status(201).json({ 
      message: "User created successfully", 
      user: userWithoutPassword 
    });

  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// User Login Endpoint
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    // Find user by email
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (error || !user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Remove password from response
    const { password: _, ...userWithoutPassword } = user;

    res.json({ 
      message: "Login successful", 
      user: userWithoutPassword 
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Forgot Password Endpoint
app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    cleanupExpiredTokens();

    // Check if user exists
    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, username")
      .eq("email", email)
      .single();

    if (error || !user) {
      return res.json({ 
        message: "If an account with that email exists, a password reset link has been sent" 
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 60 * 60 * 1000);

    passwordResetTokens.set(resetToken, {
      userId: user.id,
      email: user.email,
      username: user.username,
      expiresAt: tokenExpiry
    });

    console.log(`Password reset token for ${email}: ${resetToken}`);
    console.log(`Demo reset link: http://localhost:3000/reset-password?token=${resetToken}`);

    res.json({ 
      message: "If an account with that email exists, a password reset link has been sent",
      demoResetToken: resetToken
    });

  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Reset Password Endpoint
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ message: "Token and new password are required" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    cleanupExpiredTokens();

    const tokenData = passwordResetTokens.get(token);
    
    if (!tokenData) {
      return res.status(400).json({ message: "Invalid or expired reset token" });
    }

    if (new Date() > tokenData.expiresAt) {
      passwordResetTokens.delete(token);
      return res.status(400).json({ message: "Reset token has expired" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update user password
    const { error: updateError } = await supabase
      .from("users")
      .update({ password: hashedPassword })
      .eq("id", tokenData.userId);

    if (updateError) {
      console.error("Password update error:", updateError);
      return res.status(500).json({ message: "Failed to reset password" });
    }

    // Remove used token
    passwordResetTokens.delete(token);

    res.json({ 
      message: "Password reset successfully! You can now login with your new password." 
    });

  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Validate Reset Token Endpoint
app.post("/api/auth/validate-reset-token", async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ message: "Token is required" });
    }

    cleanupExpiredTokens();

    const tokenData = passwordResetTokens.get(token);
    
    if (!tokenData) {
      return res.status(400).json({ 
        valid: false,
        message: "Invalid or expired reset token" 
      });
    }

    if (new Date() > tokenData.expiresAt) {
      passwordResetTokens.delete(token);
      return res.status(400).json({ 
        valid: false,
        message: "Reset token has expired" 
      });
    }

    res.json({ 
      valid: true,
      message: "Token is valid",
      email: tokenData.email
    });

  } catch (error) {
    console.error("Validate token error:", error);
    res.status(500).json({ 
      valid: false,
      message: "Internal server error" 
    });
  }
});

// Improved middleware to verify user
const verifyUser = async (req, res, next) => {
  try {
    const userId = req.headers['user-id'];
    const userEmail = req.headers['user-email'];

    if (!userId || !userEmail) {
      return res.status(401).json({ message: "Authentication required" });
    }

    // Verify user exists
    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, username")
      .eq("id", userId)
      .eq("email", userEmail)
      .single();

    if (error || !user) {
      return res.status(401).json({ message: "Invalid user credentials" });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    return res.status(500).json({ message: "Authentication failed" });
  }
};

// Get user profile (protected)
app.get("/api/auth/profile", verifyUser, async (req, res) => {
  try {
    res.json({ user: req.user });
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).json({ message: "Failed to fetch profile" });
  }
});

// Enhanced user orders endpoint
app.get("/api/orders/user", verifyUser, async (req, res) => {
  try {
    const user = req.user;
    
    console.log('Fetching orders for user:', user.email, user.username);

    // Get orders that match either the user's email or username
    const { data: orders, error } = await supabase
      .from("orders")
      .select("*")
      .or(`customer_email.eq.${user.email},customer_name.eq.${user.username}`)
      .order('id', { ascending: false });

    if (error) {
      console.error('Supabase error:', error);
      throw error;
    }

    console.log('Found orders:', orders?.length);

    // Get order items for each order
    const ordersWithItems = await Promise.all(
      (orders || []).map(async (order) => {
        try {
          const { data: items, error: itemsError } = await supabase
            .from("order_items")
            .select(`
              *,
              products:product_id (
                product_name,
                description,
                image_url,
                total_amount
              )
            `)
            .eq('order_id', order.id);

          if (itemsError) {
            console.error('Error fetching items for order', order.id, itemsError);
            return {
              ...order,
              cart: [],
              error: 'Failed to load order items'
            };
          }

          // Transform items to match frontend format
          const cart = items.map(item => ({
            id: item.product_id,
            product_name: item.products?.product_name || 'Unknown Product',
            description: item.products?.description || '',
            image_url: item.products?.image_url || '',
            total_amount: item.products?.total_amount || item.price,
            quantity: item.quantity,
            price: item.price
          }));

          return {
            id: order.id,
            customer_name: order.customer_name,
            customer_phone: order.customer_phone,
            customer_address: order.customer_address,
            customer_email: order.customer_email,
            total: order.total_amount,
            status: order.status,
            created_at: order.created_at,
            updated_at: order.updated_at,
            cart: cart
          };
        } catch (itemError) {
          console.error('Error processing order items for order', order.id, itemError);
          return {
            ...order,
            cart: [],
            error: 'Failed to process order items'
          };
        }
      })
    );

    res.json(ordersWithItems);
  } catch (error) {
    console.error("Error fetching user orders:", error);
    res.status(500).json({ message: "Failed to fetch orders", error: error.message });
  }
});

// Public endpoint to create order
app.post("/api/orders", async (req, res) => {
  const { customer_name, customer_phone, customer_address, cart, total, customer_email } = req.body;

  if (!customer_name || !customer_phone || !customer_address || !cart || cart.length === 0) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    // Insert order with customer email for user association
    const { data: orderData, error: orderError } = await supabase
      .from("orders")
      .insert([{
        customer_name,
        customer_phone,
        customer_address,
        customer_email: customer_email || null,
        total_amount: total,
        status: 'pending'
      }])
      .select();

    if (orderError) throw orderError;
    const orderId = orderData[0].id;

    // Insert order items
    const orderItems = cart.map(item => ({
      order_id: orderId,
      product_id: item.id,
      quantity: item.quantity,
      price: item.total_amount || item.price,
    }));

    const { error: itemsError } = await supabase.from("order_items").insert(orderItems);
    if (itemsError) throw itemsError;

    res.json({ message: "Order created successfully", orderId });

  } catch (err) {
    console.error("Order creation error:", err);
    res.status(500).json({ message: "Failed to create order", error: err.message });
  }
});

// Get all products (public)
app.get("/api/products", async (req, res) => {
  try {
    const { data: products, error } = await supabase
      .from("products")
      .select("*")
      .order('product_name');

    if (error) throw error;
    res.json(products || []);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ message: "Failed to fetch products", error: error.message });
  }
});

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "Server is running" });
});

// Root endpoint
app.get("/", (req, res) => {
  res.json({ message: "Fast Food API is running!" });
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ message: "Endpoint not found" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
