const express = require("express");
const app = express();
const mongodb = require("mongodb");
const dotenv = require("dotenv").config();
const mongoclient = mongodb.MongoClient;
const URL = process.env.DB;
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const SECURT = process.env.jwt_secret;
const rn = require("random-number");

const options = {
  min: 1000,
  max: 9999,
  integer: true,
};

//Middleware
app.use(express.json());
app.use(
  cors({
    origin: "https://crmapp-ecom.netlify.app",
  })
);

// Register
app.post("/register", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("crm");
    const collection = db.collection("user_signifier");
    const userexist = await collection.findOne({ email: req.body.email });
    if (userexist) {
      res.status(201).json({ message: "exist" });
    } else {
      const salt1 = await bcrypt.genSalt(10);
      const hash1 = await bcrypt.hash(req.body.password, salt1);
      req.body.password = hash1;
      const salt2 = await bcrypt.genSalt(10);
      const hash2 = await bcrypt.hash(req.body.confirm_password, salt2);
      req.body.confirm_password = hash2;
      await collection.insertOne({ ...req.body, role: "user" });
      await connection.close();
      res.status(201).json({ message: "register success" });
    }
  } catch (error) {
    console.log(error);
    res.status(400).json({ message: "something went wrong" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("crm");
    const collection = db.collection("user_signifier");
    const user = await collection.findOne({
      email: req.body.email,
      role: "user",
    });
    if (user) {
      const user_compare = await bcrypt.compare(
        req.body.password,
        user.password
      );
      if (user_compare) {
        const token = jwt.sign({ id: user._id }, SECURT);
        res.json({ role: "user", token });
      } else {
        res.status(200).json({ message: "user Password Is Wrong" });
      }
    } else if (user == null) {
      const admin = await collection.findOne({
        email: req.body.email,
        role: "admin",
      });
      if (admin) {
        const admin_compare = await bcrypt.compare(
          req.body.password,
          admin.password
        );
        if (admin_compare) {
          const token = jwt.sign({ id: admin._id }, SECURT);
          res.json({ role: "admin", token });
        } else {
          res.status(200).json({ message: "admin Password Is Wrong" });
        }
      } else {
        res.status(200).json({ message: "user not found" });
      }
    }
  } catch (error) {
    console.log(error);
    res.status(400).json({ message: "something went wrong" });
  }
});

// Email config
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD,
  },
});

// Forgot Password mail sent
app.post("/sendpasswordlink", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("crm");
    const collection = db.collection("user_signifier");
    const userfind = await collection.findOne({ email: req.body.email });
    if (userfind) {
      let randomnum = rn(options);
      const setrandomnum = await collection.findOneAndUpdate(
        { email: req.body.email },
        {
          $set: {
            rnum: randomnum,
          },
        }
      );

      if (setrandomnum) {
        console.log(setrandomnum);
        const mailOptions = {
          from: process.env.EMAIL,
          to: req.body.email,
          subject: "Sending Email For password Reset",
          html: `<b>Please <a href='https://crmapp-ecom.netlify.app/verify-user/${setrandomnum.value._id}/${randomnum}'> Click here</a> to reset your password</b>`,
        };
        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            res.status(401).json({ status: 401, message: "email not send" });
          } else {
            res
              .status(201)
              .json({ status: 201, message: "Email sent Succsfully" });
          }
        });
      }
    } else {
      res.status(401).json({ status: 401, message: "user not send" });
    }
  } catch (error) {
    console.log(error);
  }
});

//verify user to forgot password
app.post("/verify-user/:id/:randomnum", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("crm");
    const collection = db.collection("user_signifier");
    const userfind = await collection.findOne({
      _id: mongodb.ObjectId(req.params.id),
    });

    if (userfind.rnum == req.params.randomnum) {
      res.status(200).json({ message: "user verified" });
    } else {
      res.status(400).json({ message: "Invalid url" });
    }
    await connection.close();
  } catch (error) {
    console.log(error);
  }
});

//Update new password
app.put("/password-update/:id", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("crm");
    const collection = db.collection("user_signifier");

    const salt1 = await bcrypt.genSalt(10);
    const hash1 = await bcrypt.hash(req.body.password, salt1);
    req.body.password = hash1;

    const salt2 = await bcrypt.genSalt(10);
    const hash2 = await bcrypt.hash(req.body.confirm_password, salt2);
    req.body.confirm_password = hash2;

    const users = await collection.findOneAndUpdate(
      { _id: mongodb.ObjectId(req.params.id) },
      {
        $set: {
          password: hash1,
          confirm_password: hash2,
        },
      }
    );
    await connection.close();
    res.json({ message: "Password updated successfully" });
  } catch (error) {
    console.log(error);
  }
});

const authorize = (req, res, next) => {
  if (req.headers.authorization) {
    try {
      const verify = jwt.verify(req.headers.authorization, SECURT);
      if (verify) {
        next();
      }
    } catch (error) {
      res.json({ message: "unautrhorized" });
    }
  } else {
    res.json({ message: "unautrhorized" });
  }
};

// get products
app.get("/products", authorize, async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("crm");
    const collection = db.collection("products");
    const users = await collection
      .find({
        $or: [
          {
            isDeleted: { $exists: false },
          },
          {
            isDeleted: false,
          },
        ],
      })
      .toArray();
    await connection.close();

    res.json(users);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

// remove product
app.delete("/remove-product/:id", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("crm");
    const collection = db.collection("products");
    const deleteitems = await collection.findOneAndUpdate(
      { _id: mongodb.ObjectId(req.params.id) },
      { $set: { isDeleted: true } }
    );
    await connection.close();

    res.json(deleteitems);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

// add product
app.post("/add-product", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("crm");
    const collection = db.collection("products");
    const added_products = await collection.insertOne({
      ...req.body,
      isDeleted: false,
    });
    await connection.close();

    res.json({ message: "product added", added_products });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

// get single product
app.get("/get-product/:id", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("crm");
    const collection = db.collection("products");
    const single_product = await collection
      .find({ _id: mongodb.ObjectId(req.params.id) })
      .toArray();
    await connection.close();

    res.json(single_product);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

// update product
app.put("/update-product/:id", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("crm");
    const collection = db.collection("products");
    const update = await collection.findOneAndUpdate(
      { _id: mongodb.ObjectId(req.params.id) },
      {
        $set: req.body,
      }
    );
    await connection.close();

    res.json(update);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

//add to cart
app.post("/addtocart/:id", async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("crm");
    const collection = db.collection("products");
    const collection2 = db.collection("product-cart");
    const product = await collection
      .find({ _id: mongodb.ObjectId(req.params.id) })
      .toArray();
    await collection2.insertOne({ product });
    await connection.close();

    res.json({ product, message: "item added to cart" });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

//get items from cart
app.get("/get_cart_items", authorize, async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("crm");
    const collection = db.collection("product-cart");
    const cartitems = await collection.find({}).toArray();
    await connection.close();

    res.json(cartitems);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

//remove item from cart
app.delete("/remove_cart_item/:id", authorize, async (req, res) => {
  try {
    const connection = await mongoclient.connect(URL);
    const db = connection.db("crm");
    const collection = db.collection("product-cart");
    const deleteitems = await collection.deleteOne({
      _id: mongodb.ObjectId(req.params.id),
    });
    await connection.close();

    res.json(deleteitems);
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "something went wrong" });
  }
});

// Set port.
app.listen(8000);
