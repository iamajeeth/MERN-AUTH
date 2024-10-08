import Product from "../models/productModel";

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
