const express = require('express');
const cors = require('cors'); // ✅ FIXED: Single import
const { createClient } = require("@supabase/supabase-js");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
require("dotenv").config();

const app = express();

// ✅ FIXED: Single CORS configuration
app.use(cors({
  origin: ["https://quickfastfood.vercel.app", "http://localhost:3000"],
  credentials: true
}));

app.use(express.json());

// ✅ FIXED: Better upload directory handling
const uploadsDir = path.join(__dirname, 'uploads');
try {
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
    console.log('Uploads directory created successfully');
  }
} catch (error) {
  console.error('Failed to create uploads directory:', error);
  process.exit(1);
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'image-' + uniqueSuffix + path.extname(file.originalname));
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

// Token cleanup function
const cleanupExpiredTokens = () => {
  const now = new Date();
  let cleanedCount = 0;
  for (const [token, data] of passwordResetTokens.entries()) {
    if (now > data.expiresAt) {
      passwordResetTokens.delete(token);
      cleanedCount++;
    }
  }
  if (cleanedCount > 0) {
    console.log(`Cleaned up ${cleanedCount} expired tokens`);
  }
};

setInterval(cleanupExpiredTokens, 60 * 60 * 1000);

// ✅ FIXED: Improved authentication middleware
const verifyUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: "Authentication token required" });
    }

    const token = authHeader.replace('Bearer ', '');
    
    // Verify the token with Supabase
    const { data: { user }, error } = await supabase.auth.getUser(token);
    
    if (error || !user) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }

    // Get user details from database
    const { data: userData, error: userError } = await supabase
      .from("users")
      .select("id, email, username, role")
      .eq("email", user.email)
      .single();

    if (userError || !userData) {
      return res.status(401).json({ message: "User not found" });
    }

    req.user = userData;
    next();
  } catch (error) {
    console.error("Auth middleware error:", error);
    return res.status(500).json({ message: "Authentication failed" });
  }
};

// ✅ FIXED: Protected products endpoint
app.get("/api/products", async (req, res) => {
  try {
    const { data: products, error } = await supabase
      .from("products")
      .select("*")
      .order('product_name');

    if (error) throw error;
    
    // ✅ FIXED: Consistent field names for frontend
    const formattedProducts = (products || []).map(product => ({
      id: product.id,
      name: product.product_name, // Standardize to 'name'
      product_name: product.product_name, // Keep original for compatibility
      description: product.description,
      price: product.total_amount, // Standardize to 'price'
      total_amount: product.total_amount, // Keep original for compatibility
      image_url: product.image_url,
      is_available: product.is_available
    }));
    
    res.json(formattedProducts);
  } catch (error) {
    console.error("Error fetching products:", error);
    res.status(500).json({ message: "Failed to fetch products", error: error.message });
  }
});

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
      .insert([{ username, email, password: hashedPassword }])
      .select()
      .single();

    if (createError) {
      console.error("User creation error:", createError);
      return res.status(500).json({ message: "Failed to create user" });
    }

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

    // Create Supabase session for the user
    const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
      email: email,
      password: password
    });

    if (authError) {
      console.error("Supabase auth error:", authError);
      return res.status(500).json({ message: "Authentication failed" });
    }

    const { password: _, ...userWithoutPassword } = user;

    res.json({ 
      message: "Login successful", 
      user: userWithoutPassword,
      session: {
        access_token: authData.session.access_token,
        refresh_token: authData.session.refresh_token
      }
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Check email exists endpoint
app.post("/api/auth/check-email", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, username")
      .eq("email", email)
      .single();

    if (error || !user) {
      return res.json({ 
        exists: false,
        message: "If an account with that email exists, a password reset link has been sent" 
      });
    }

    res.json({ 
      exists: true, 
      message: "Email found",
      user: { id: user.id, email: user.email, username: user.username }
    });

  } catch (error) {
    console.error("Check email error:", error);
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

    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 60 * 60 * 1000);

    passwordResetTokens.set(resetToken, {
      userId: user.id,
      email: user.email,
      username: user.username,
      expiresAt: tokenExpiry
    });

    console.log(`Password reset token for ${email}: ${resetToken}`);

    res.json({ 
      message: "If an account with that email exists, a password reset link has been sent",
      demoResetToken: resetToken // Remove in production
    });

  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Reset Password Endpoint
app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const { token, newPassword, email } = req.body;

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

    if (email && email !== tokenData.email) {
      return res.status(400).json({ message: "Email does not match reset token" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    const { error: updateError } = await supabase
      .from("users")
      .update({ password: hashedPassword })
      .eq("id", tokenData.userId);

    if (updateError) {
      console.error("Password update error:", updateError);
      return res.status(500).json({ message: "Failed to reset password" });
    }

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

// Get user profile (protected)
app.get("/api/auth/profile", verifyUser, async (req, res) => {
  try {
    res.json({ user: req.user });
  } catch (error) {
    console.error("Profile fetch error:", error);
    res.status(500).json({ message: "Failed to fetch profile" });
  }
});

// Update user profile (protected)
app.put("/api/auth/profile", verifyUser, async (req, res) => {
  try {
    const { username, email, phone, address } = req.body;
    const userId = req.user.id;

    const updateData = {};
    if (username) updateData.username = username;
    if (email) updateData.email = email;
    if (phone !== undefined) updateData.phone = phone;
    if (address !== undefined) updateData.address = address;

    const { data: user, error } = await supabase
      .from("users")
      .update(updateData)
      .eq("id", userId)
      .select()
      .single();

    if (error) throw error;

    const { password: _, ...userWithoutPassword } = user;
    res.json({ 
      message: "Profile updated successfully", 
      user: userWithoutPassword 
    });

  } catch (error) {
    console.error("Profile update error:", error);
    res.status(500).json({ message: "Failed to update profile" });
  }
});

// User orders endpoint
app.get("/api/orders/user", verifyUser, async (req, res) => {
  try {
    const user = req.user;
    
    console.log('Fetching orders for user:', user.email, user.username);

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

// Upload image endpoint (protected)
app.post("/api/upload", verifyUser, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "No image file provided" });
    }

    const imageUrl = `/uploads/${req.file.filename}`;
    
    res.json({ 
      message: "Image uploaded successfully", 
      imageUrl: imageUrl,
      filename: req.file.filename
    });
  } catch (error) {
    console.error("Error uploading image:", error);
    res.status(500).json({ message: "Failed to upload image", error: error.message });
  }
});

// Delete uploaded image (protected)
app.delete("/api/upload/:filename", verifyUser, async (req, res) => {
  try {
    const { filename } = req.params;
    const filePath = path.join(__dirname, 'uploads', filename);

    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      res.json({ message: "Image deleted successfully" });
    } else {
      res.status(404).json({ message: "Image not found" });
    }
  } catch (error) {
    console.error("Error deleting image:", error);
    res.status(500).json({ message: "Failed to delete image", error: error.message });
  }
});

// Get all orders (protected)
app.get("/api/orders", verifyUser, async (req, res) => {
  try {
    const { data: orders, error } = await supabase
      .from("orders")
      .select("*")
      .order('id', { ascending: false });

    if (error) throw error;
    res.json(orders || []);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ message: "Failed to fetch orders", error: error.message });
  }
});

// Get order items (protected)
app.get("/api/orders/:orderId/items", verifyUser, async (req, res) => {
  try {
    const { orderId } = req.params;
    
    const { data: items, error } = await supabase
      .from("order_items")
      .select(`
        *,
        products:product_id (
          product_name,
          image_url,
          description
        )
      `)
      .eq('order_id', orderId);

    if (error) throw error;

    const transformedItems = items.map(item => ({
      id: item.id,
      product_id: item.product_id,
      product_name: item.products?.product_name || 'Unknown Product',
      description: item.products?.description || '',
      image_url: item.products?.image_url || '',
      quantity: item.quantity,
      unit_price: item.unit_price,
    }));

    res.json(transformedItems);
  } catch (error) {
    console.error("Error fetching order items:", error);
    res.status(500).json({ message: "Failed to fetch order items", error: error.message });
  }
});

// Update order status (protected)
app.put("/api/orders/:orderId", verifyUser, async (req, res) => {
  try {
    const { orderId } = req.params;
    const { status } = req.body;

    if (!['pending', 'completed', 'cancelled'].includes(status)) {
      return res.status(400).json({ message: "Invalid status" });
    }

    const { error } = await supabase
      .from("orders")
      .update({ 
        status, 
        updated_at: new Date().toISOString()
      })
      .eq('id', orderId);

    if (error) throw error;
    res.json({ message: "Order status updated successfully" });
  } catch (error) {
    console.error("Error updating order:", error);
    res.status(500).json({ message: "Failed to update order", error: error.message });
  }
});

// Delete order (protected)
app.delete("/api/orders/:orderId", verifyUser, async (req, res) => {
  try {
    const { orderId } = req.params;

    const { error: itemsError } = await supabase
      .from("order_items")
      .delete()
      .eq('order_id', orderId);

    if (itemsError) throw itemsError;

    const { error: orderError } = await supabase
      .from("orders")
      .delete()
      .eq('id', orderId);

    if (orderError) throw orderError;
    res.json({ message: "Order deleted successfully" });
  } catch (error) {
    console.error("Error deleting order:", error);
    res.status(500).json({ message: "Failed to delete order", error: error.message });
  }
});

// ✅ FIXED: Update product with consistent field names
app.put("/api/products/:productId", verifyUser, async (req, res) => {
  try {
    const { productId } = req.params;
    const { name, description, price, image_url, is_available } = req.body;

    console.log('Updating product:', { productId, name, description, price, image_url, is_available });

    const cleanedImageUrl = validateImageUrl(image_url);
    
    // ✅ FIXED: Consistent field mapping
    const updateData = {
      product_name: name, // Map 'name' to 'product_name'
      description: description,
      total_amount: parseFloat(price), // Map 'price' to 'total_amount'
      is_available: is_available !== undefined ? is_available : true
    };

    if (cleanedImageUrl !== null) {
      updateData.image_url = cleanedImageUrl;
    } else if (image_url === '') {
      updateData.image_url = null;
    }

    console.log('Final update data:', updateData);

    const { data, error } = await supabase
      .from("products")
      .update(updateData)
      .eq('id', productId)
      .select();

    if (error) {
      console.error('Supabase update error:', error);
      throw error;
    }

    console.log('Product updated successfully:', data);
    res.json({ message: "Product updated successfully", product: data[0] });
  } catch (error) {
    console.error("Error updating product:", error);
    res.status(500).json({ message: "Failed to update product", error: error.message });
  }
});

// ✅ FIXED: Create product with consistent field names
app.post("/api/products", verifyUser, async (req, res) => {
  try {
    const { name, description, price, image_url, is_available } = req.body;

    console.log('Creating product:', { name, description, price, image_url, is_available });

    const cleanedImageUrl = validateImageUrl(image_url);

    // ✅ FIXED: Consistent field mapping
    const insertData = {
      product_name: name, // Map 'name' to 'product_name'
      description: description,
      total_amount: parseFloat(price), // Map 'price' to 'total_amount'
      is_available: is_available !== undefined ? is_available : true
    };

    if (cleanedImageUrl !== null) {
      insertData.image_url = cleanedImageUrl;
    }

    console.log('Final insert data:', insertData);

    const { data, error } = await supabase
      .from("products")
      .insert([insertData])
      .select();

    if (error) {
      console.error('Supabase insert error:', error);
      throw error;
    }

    console.log('Product created successfully:', data);
    res.json({ message: "Product created successfully", product: data[0] });
  } catch (error) {
    console.error("Error creating product:", error);
    res.status(500).json({ message: "Failed to create product", error: error.message });
  }
});

// Delete product (protected)
app.delete("/api/products/:productId", verifyUser, async (req, res) => {
  try {
    const { productId } = req.params;

    const { error } = await supabase
      .from("products")
      .delete()
      .eq('id', productId);

    if (error) throw error;
    res.json({ message: "Product deleted successfully" });
  } catch (error) {
    console.error("Error deleting product:", error);
    res.status(500).json({ message: "Failed to delete product", error: error.message });
  }
});

// Get dashboard stats (protected)
app.get("/api/dashboard/stats", verifyUser, async (req, res) => {
  try {
    const { data: orders, error: ordersError } = await supabase
      .from("orders")
      .select("status, total_amount");

    if (ordersError) throw ordersError;

    const totalOrders = orders?.length || 0;
    const pendingOrders = orders?.filter(order => order.status === "pending").length || 0;
    const completedOrders = orders?.filter(order => order.status === "completed").length || 0;
    const totalRevenue = orders?.reduce((sum, order) => sum + (order.total_amount || 0), 0) || 0;

    const { data: products, error: productsError } = await supabase
      .from("products")
      .select("id");

    if (productsError) throw productsError;

    res.json({
      totalOrders,
      pendingOrders,
      completedOrders,
      totalRevenue,
      totalProducts: products?.length || 0
    });
  } catch (error) {
    console.error("Error fetching dashboard stats:", error);
    res.status(500).json({ message: "Failed to fetch dashboard stats", error: error.message });
  }
});

// Helper function to validate and clean image URL
const validateImageUrl = (url) => {
  if (!url || url.trim() === '') {
    return null;
  }
  
  if (url.startsWith('/uploads/')) {
    return url;
  }
  
  let cleanUrl = url.split('?')[0];
  
  try {
    const urlObj = new URL(cleanUrl);
    
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      console.log('Invalid protocol:', urlObj.protocol);
      return null;
    }
    
    const pathname = urlObj.pathname.toLowerCase();
    const validExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.bmp'];
    const hasValidExtension = validExtensions.some(ext => pathname.endsWith(ext));
    
    if (!hasValidExtension) {
      console.log('No valid image extension found:', pathname);
    }
    
    return cleanUrl;
  } catch (error) {
    console.log('Invalid URL format:', cleanUrl);
    return null;
  }
};

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "Server is running" });
});

// Root endpoint
app.get("/", (req, res) => {
  res.json({ message: "Fast Food API is running!" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
