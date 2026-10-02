
const jwt = require("jsonwebtoken");

const Admin = require("../models/Admin");
const User = require("../models/User");



const normalizeIndianPhone = (value) => {
  if (value === undefined || value === null) {
    return null;
  }

  const phone = String(value)
    .trim()
    .replace(/[\s()-]/g, "");

  if (/^[6-9]\d{9}$/.test(phone)) {
    return `+91${phone}`;
  }

  if (/^\+91[6-9]\d{9}$/.test(phone)) {
    return phone;
  }

  return null;
};



const createAccessToken = (user) => {
  return jwt.sign(
    {
      userId: user._id,
      email: user.email,
      phone: user.phone,
      role: user.role,
    },
    process.env.JWT_SECRET || "my_secret_key",
    {
      expiresIn: "24h",
    }
  );
};



const adminLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required",
      });
    }

    const admin = await Admin.findOne({
      email: email.toLowerCase(),
    });

    if (!admin || password !== admin.password) {
      return res.status(401).json({
        message: "Invalid email or password",
      });
    }

    const accessToken = createAccessToken(admin);

    res.json({
      message: "Login successful",
      accessToken,
      user: {
        id: admin._id,
        email: admin.email,
        role: admin.role || "ADMIN",
      },
    });
  } catch (error) {
    console.error("Admin login error:", error);

    res.status(500).json({
      message: "Server error",
    });
  }
};


const sendOtp = async (req, res) => {
  try {
    const phone = normalizeIndianPhone(req.body.phone);

    if (!phone) {
      return res.status(400).json({
        message: "Enter a valid Indian 10-digit phone number",
      });
    }

    console.log(
      "Staff login requested for phone ending in",
      phone.slice(-4)
    );

    // Find existing user
    let user = await User.findOne({ phone });

    // Create staff user if not found
    if (!user) {
      user = await User.create({
        phone,
        role: "STAFF",
      });
    }

    res.json({
      message: "OTP sent successfully",
    });
  } catch (error) {
    console.error("Send OTP error:", error);

    res.status(500).json({
      message: "Server error",
    });
  }
};



const verifyOtp = async (req, res) => {
  try {
    const phone = normalizeIndianPhone(req.body.phone);

    let { otp } = req.body;

    if (!phone || !otp) {
      return res.status(400).json({
        message:
          "A valid Indian phone number and OTP are required",
      });
    }

    otp = otp.toString().trim();

    

    const user = await User.findOne({ phone });

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    

    if (otp !== "461933") {
      return res.status(400).json({
        message: "Invalid OTP",
      });
    }

    console.log(
      "Staff logged in successfully using static OTP"
    );

    

    const accessToken = createAccessToken(user);



    res.json({
      message: "Login successful",
      accessToken,
      user: {
        id: user._id,
        email: user.email,
        phone: user.phone,
        role: user.role || "STAFF",
      },
    });
  } catch (error) {
    console.error("Verify OTP error:", error);

    res.status(500).json({
      message: "Server error",
    });
  }
};


const logout = (req, res) => {
  res.json({
    message: "Logout successful",
  });
};


module.exports = {
  adminLogin,
  sendOtp,
  verifyOtp,
  logout,
};
