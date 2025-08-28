// routes/wallet.js
const express = require("express");
const router = express.Router();
const User = require("./Models/User");
const authMiddleware = require("./Routes/Auth");

// ✅ Add money to wallet
router.post("/add", authMiddleware, async (req, res) => {
  try {
    const { amount, description } = req.body;
    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, message: "Invalid amount" });
    }

    req.user.wallet.balance += amount;
    req.user.wallet.transactions.unshift({
      type: "credit",
      amount,
      description: description || "Wallet Top-up"
    });

    await req.user.save();

    res.json({
      success: true,
      message: "Wallet credited successfully",
      balance: req.user.wallet.balance
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ✅ Deduct money from wallet
router.post("/deduct", authMiddleware, async (req, res) => {
  try {
    const { amount, description } = req.body;
    if (!amount || amount <= 0) {
      return res.status(400).json({ success: false, message: "Invalid amount" });
    }

    if (req.user.wallet.balance < amount) {
      return res.status(400).json({ success: false, message: "Insufficient balance" });
    }

    req.user.wallet.balance -= amount;
    req.user.wallet.transactions.unshift({
      type: "debit",
      amount,
      description: description || "Deduction"
    });

    await req.user.save();

    res.json({
      success: true,
      message: "Wallet debited successfully",
      balance: req.user.wallet.balance
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ✅ Get balance
router.get("/balance", authMiddleware, (req, res) => {
  res.json({
    success: true,
    balance: req.user.wallet.balance
  });
});

// ✅ Get transaction history
router.get("/history", authMiddleware, (req, res) => {
  res.json({
    success: true,
    transactions: req.user.wallet.transactions
  });
});

module.exports = router;
