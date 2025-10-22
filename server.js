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
const cors = require("cors");
app.use(cors({
  origin: "https://quickfastfood.vercel.app"
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
  // Check if the file is an image
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
    fileSize: 5 * 1024 * 1024, // 5MB limit
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

// In-memory store for password reset tokens with automatic cleanup
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

// Run cleanup every hour
setInterval(cleanupExpiredTokens, 60 * 60 * 1000);

// User Registration Endpoint
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
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

    // Validation
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

// Check email exists endpoint
app.post("/api/auth/check-email", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    // Check if user exists
    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, username")
      .eq("email", email)
      .single();

    if (error || !user) {
      // For security, don't reveal if email exists or not
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

    // Clean up expired tokens first
    cleanupExpiredTokens();

    // Check if user exists
    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, username")
      .eq("email", email)
      .single();

    if (error || !user) {
      // For security, don't reveal if email exists or not
      return res.json({ 
        message: "If an account with that email exists, a password reset link has been sent" 
      });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour expiry

    // Store token in memory (in production, store in database)
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
      // For demo purposes only - remove in production
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
    const { token, newPassword, email } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ message: "Token and new password are required" });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    // Clean up expired tokens first
    cleanupExpiredTokens();

    // Verify token exists and is not expired
    const tokenData = passwordResetTokens.get(token);
    
    if (!tokenData) {
      return res.status(400).json({ message: "Invalid or expired reset token" });
    }

    if (new Date() > tokenData.expiresAt) {
      // Clean up expired token
      passwordResetTokens.delete(token);
      return res.status(400).json({ message: "Reset token has expired" });
    }

    // Optional: Verify email matches token (for extra security)
    if (email && email !== tokenData.email) {
      return res.status(400).json({ message: "Email does not match reset token" });
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

    // Clean up expired tokens first
    cleanupExpiredTokens();

    // Verify token exists and is not expired
    const tokenData = passwordResetTokens.get(token);
    
    if (!tokenData) {
      return res.status(400).json({ 
        valid: false,
        message: "Invalid or expired reset token" 
      });
    }

    if (new Date() > tokenData.expiresAt) {
      // Clean up expired token
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

// FIXED: Improved middleware to verify user (simple session-based auth)
const verifyUser = async (req, res, next) => {
  try {
    const userId = req.headers['user-id'];
    const userEmail = req.headers['user-email'];
    // Verify user exists
    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, username")
      .eq("id", userId)
      .eq("email", userEmail)
      .single();


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

// FIXED: Improved user orders endpoint with better error handling
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

// Public endpoint to create order (with user association)
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
        customer_email: customer_email || null, // Store email for user association
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
      price: item.total_amount || item.price, // Handle both naming conventions
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

    // Construct the URL for the uploaded file
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

    // Check if file exists and delete it
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

    // Transform the data to include product information
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

    // First delete order items
    const { error: itemsError } = await supabase
      .from("order_items")
      .delete()
      .eq('order_id', orderId);

    if (itemsError) throw itemsError;

    // Then delete the order
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

// Update product (protected)
app.put("/api/products/:productId", verifyUser, async (req, res) => {
  try {
    const { productId } = req.params;
    const { name, description, price, image_url, is_available } = req.body;

    console.log('Updating product:', { productId, name, description, price, image_url, is_available });

    // Validate and clean image URL
    const cleanedImageUrl = validateImageUrl(image_url);
    
    const updateData = {
      product_name: name,
      description: description,
      total_amount: parseFloat(price),
      is_available: is_available !== undefined ? is_available : true
    };

    // Only add image_url if it's valid, otherwise keep existing one
    if (cleanedImageUrl !== null) {
      updateData.image_url = cleanedImageUrl;
    } else if (image_url === '') {
      // If empty string is provided, set to null
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

// Create new product (protected)
app.post("/api/products", verifyUser, async (req, res) => {
  try {
    const { name, description, price, image_url, is_available } = req.body;

    console.log('Creating product:', { name, description, price, image_url, is_available });

    // Validate and clean image URL
    const cleanedImageUrl = validateImageUrl(image_url);

    const insertData = {
      product_name: name,
      description: description,
      total_amount: parseFloat(price),
      is_available: is_available !== undefined ? is_available : true
    };

    // Only add image_url if it's valid
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
    // Get total orders
    const { data: orders, error: ordersError } = await supabase
      .from("orders")
      .select("status, total_amount");

    if (ordersError) throw ordersError;

    const totalOrders = orders?.length || 0;
    const pendingOrders = orders?.filter(order => order.status === "pending").length || 0;
    const completedOrders = orders?.filter(order => order.status === "completed").length || 0;
    const totalRevenue = orders?.reduce((sum, order) => sum + (order.total_amount || 0), 0) || 0;
    const averageOrderValue = totalOrders > 0 ? totalRevenue / totalOrders : 0;

    // Get total products
    const { data: products, error: productsError } = await supabase
      .from("products")
      .select("id");

    if (productsError) throw productsError;

    res.json({
      totalOrders,
      pendingOrders,
      completedOrders,
      totalRevenue,
      averageOrderValue,
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
  
  // If it's already a local file path (starts with /uploads), return as is
  if (url.startsWith('/uploads/')) {
    return url;
  }
  
  // Clean the URL - remove any cache busting parameters that might cause issues
  let cleanUrl = url.split('?')[0]; // Remove query parameters
  
  // Validate URL format
  try {
    const urlObj = new URL(cleanUrl);
    
    // Check if it's a valid HTTP/HTTPS URL
    if (!['http:', 'https:'].includes(urlObj.protocol)) {
      console.log('Invalid protocol:', urlObj.protocol);
      return null;
    }
    
    // Check for common image file extensions
    const pathname = urlObj.pathname.toLowerCase();
    const validExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.bmp'];
    const hasValidExtension = validExtensions.some(ext => pathname.endsWith(ext));
    
    if (!hasValidExtension) {
      console.log('No valid image extension found:', pathname);
      // Still allow the URL as some image URLs might not have extensions
    }
    
    return cleanUrl;
  } catch (error) {
    console.log('Invalid URL format:', cleanUrl);
    return null;
  }
};

// Admin Management Endpoints

// Get all admins (protected)
app.get("/api/admins", verifyUser, async (req, res) => {
  try {
    const { data: admins, error } = await supabase
      .from("admin_users")
      .select("*")
      .order('created_at', { ascending: false });

    if (error) throw error;
    res.json(admins || []);
  } catch (error) {
    console.error("Error fetching admins:", error);
    res.status(500).json({ message: "Failed to fetch admins", error: error.message });
  }
});

// Create new admin (protected)
app.post("/api/admins", verifyUser, async (req, res) => {
  try {
    const { email, name, password, role } = req.body;

    // Validation
    if (!email || !name || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    // Check if admin already exists
    const { data: existingAdmin, error: checkError } = await supabase
      .from("admin_users")
      .select("id")
      .eq("email", email)
      .single();

    if (existingAdmin) {
      return res.status(400).json({ message: "Admin already exists with this email" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create admin
    const { data: admin, error: createError } = await supabase
      .from("admin_users")
      .insert([
        {
          name,
          email,
          password: hashedPassword,
          role: role || 'admin',
        }
      ])
      .select()
      .single();

    if (createError) {
      console.error("Admin creation error:", createError);
      return res.status(500).json({ message: "Failed to create admin" });
    }

    // Remove password from response
    const { password: _, ...adminWithoutPassword } = admin;

    res.status(201).json({ 
      message: "Admin created successfully", 
      admin: adminWithoutPassword 
    });

  } catch (error) {
    console.error("Admin creation error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Delete admin (protected)
app.delete("/api/admins/:adminId", verifyUser, async (req, res) => {
  try {
    const { adminId } = req.params;

    // Prevent self-deletion
    const { data: admin, error: fetchError } = await supabase
      .from("admin_users")
      .select("email")
      .eq("id", adminId)
      .single();

    if (fetchError) throw fetchError;

    if (admin.email === req.user.email) {
      return res.status(400).json({ message: "You cannot delete your own account" });
    }

    const { error: deleteError } = await supabase
      .from("admin_users")
      .delete()
      .eq("id", adminId);

    if (deleteError) throw deleteError;

    res.json({ message: "Admin deleted successfully" });
  } catch (error) {
    console.error("Error deleting admin:", error);
    res.status(500).json({ message: "Failed to delete admin", error: error.message });
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
// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? error.message : undefined
  });
});

// 404 handler - FIXED VERSION
app.use((req, res, next) => {
  res.status(404).json({ message: 'Endpoint not found' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
