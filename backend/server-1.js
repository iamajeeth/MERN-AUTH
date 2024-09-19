import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
const router = express.Router();

// Load environment variables
dotenv.config();

// Initialize express
const app = express();

// Body parser
app.use(express.json());

const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, default: "user" }, // 'user' or 'admin'
  },
  { timestamps: true }
); // Automatically adds `createdAt` and `updatedAt` fields

// Encrypt password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

mongoose.model("User", userSchema);

const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, index: true },
    description: { type: String },
    price: { type: Number, required: true, min: 0 }, // Ensure price is non-negative
  },
  { timestamps: true }
); // Automatically adds `createdAt` and `updatedAt` fields

export default mongoose.model("Product", productSchema);

// Generate JWT Token
const generateToken = (user) => {
  return jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });
};

export async function protect(req, res, next) {
  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      if (!decoded || !decoded.id) {
        return res
          .status(401)
          .json({ message: "Not authorized, token invalid" });
      }

      req.user = await User.findById(decoded.id).select("-password");

      if (!req.user) {
        return res.status(401).json({ message: "User not found" });
      }

      next();
    } catch (err) {
      console.error(err); // Log the error for debugging
      return res.status(401).json({ message: "Not authorized, token failed" });
    }
  }

  if (!token) {
    return res.status(401).json({ message: "No token, authorization denied" });
  }
}

// Register a new user
export async function registerUser(req, res) {
  const { username, password, role } = req.body;

  try {
    const user = new User({ username, password, role });
    await user.save();
    res.status(201).json({ token: generateToken(user) });
  } catch (err) {
    res.status(400).json({ message: "Error creating user" });
  }
}

// Login user and return token
export async function loginUser(req, res) {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (user && (await user.matchPassword(password))) {
      res.json({ token: generateToken(user) });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  } catch (err) {
    res.status(400).json({ message: "Error logging in" });
  }
}

// List all products
export async function getProducts(req, res) {
  try {
    const products = await Product.find({});
    res.json(products);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
}

// Add a new product (Admin only)
export async function addProduct(req, res) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }
  const { name, description, price } = req.body;
  try {
    const product = new Product({ name, description, price });
    await product.save();
    res.status(201).json(product);
  } catch (err) {
    res.status(400).json({ message: "Error creating product" });
  }
}

// Update product (Admin only)
export async function updateProduct(req, res) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: "Product not found" });
    }

    const { name, description, price } = req.body;
    product.name = name || product.name;
    product.description = description || product.description;
    product.price = price || product.price;
    await product.save();
    res.json(product);
  } catch (err) {
    res.status(400).json({ message: "Error updating product" });
  }
}

router.post("/register", registerUser);
router.post("/login", loginUser);
router.get("/", protect, getProducts); // List products
router.post("/", protect, addProduct); // Add a product (Admin only)
router.patch("/:id", protect, updateProduct); // Update product (Admin only)

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/products", productRoutes);

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.log(`Error: ${error.message}`);
    process.exit(1); // process code 1 means exit with failure, 0 means success
  }
};

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  connectDB();
  console.log(`Server running on port ${PORT}`);
});
