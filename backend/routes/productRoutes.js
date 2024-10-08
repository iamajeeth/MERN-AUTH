import express from "express";
import { getProducts, addProduct, updateProduct } from "../controllers/productController.js";
import { protect } from "../middlewares/authMiddleware.js";
const router = express.Router();

router.get("/", protect, getProducts); // List products
router.post("/", protect, addProduct); // Add a product (Admin only)
router.patch("/:id", protect, updateProduct); // Update product (Admin only)

export default router;
