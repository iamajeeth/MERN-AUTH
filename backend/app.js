import express from "express";
import dotenv from "dotenv";
import authRoutes from "./routes/authRoutes.js";
import productRoutes from "../routes/productRoutes.js";

// Load environment variables
dotenv.config();

// Initialize express
const app = express();

// Body parser
app.use(express.json());

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/products", productRoutes);

// Export the app
export default app;
