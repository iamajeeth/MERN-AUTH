import mongoose from "mongoose";

const productSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, index: true },
    description: { type: String },
    price: { type: Number, required: true, min: 0 }, // Ensure price is non-negative
  },
  { timestamps: true }
); // Automatically adds `createdAt` and `updatedAt` fields

export default mongoose.model("Product", productSchema);
