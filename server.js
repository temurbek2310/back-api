import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import { mongoose } from "mongoose";
import cors from "cors";
import jwt from "jsonwebtoken";
import { Headers } from "node-fetch";
import { v4 as uuid } from "uuid";
import { AuthModel } from "./models/auth.js";

const headers = new Headers();

headers.set("Content-Type", "application/json");
headers.append("Access-Control-Allow-Origin", "*");
headers.append("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
headers.append("Access-Control-Allow-Credentials", "true");
headers.append("Access-Control-Allow-Headers", "Content-Type");

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const URI = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.swgha.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const main = async (req, res) => {
  res.send("Hello World!");
  // CONNECTION TO DB
  await mongoose
    .connect(URI)
    .then((res) => {
      console.log("Connected to DB");
    })
    .catch((err) => {
      console.log(err);
    });

  // ROUTES

  // GET USER
  app.get("/user", async (req, res) => {
    try {
      const bearerHeader = req.headers["authorization"];
      const token = bearerHeader.split(" ")[1];
      const decodedToken = jwt.verify(token, process.env.PRIVATE_KEY);

      if (
        typeof bearerHeader === "undefined" ||
        decodedToken?.email !== req.query.email
      ) {
        res.status(401).json({ message: "Forbidden" });
      }
      const { email } = req.query;
      console.log({ email });
      const user = await AuthModel.findOne({ email }).exec();
      const { password, ...rest } = user["_doc"];
      console.log({ rest });
      if (!user) {
        res.status(404).json({ message: "User not found" });
        return;
      }
      res.status(200).json({ ...rest });
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "Error" });
    }
  });

  // REGISTER
  app.post("/register", async (req, res) => {
    try {
      // TAKING DATA FROM REQUEST
      const { name, email, password } = req.body;
      const id = uuid();
      const user = await AuthModel.findOne({ email }).exec();
      // ENCRYPTING PASSWORD AND ID
      const hashedToken = await jwt.sign(
        { password, id },
        process.env.PRIVATE_KEY
      );

      if (!user) {
        // CREATE MONGODB USER
        const user = await AuthModel.create({
          id,
          name,
          email,
          password: hashedToken,
        }).exec();

        // CREATING TOKEN FOR REGISTER
        const token = jwt.sign(
          { name: user?.name, email: user?.email, id: user?.id },
          process.env.PRIVATE_KEY
        );

        res.json({
          message: "User successfully created",
          id: user?.id,
          name: user?.name,
          email: user?.email,
          token,
        });
      }
      throw new Error("This email is already in use");
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
    return;
  });

  // LOGIN
  app.post("/login", async (req, res) => {
    try {
      // TAKING DATA FROM REQUEST
      const { email, password } = req.body;
      // CHECKING IF USER EXISTS
      const user = await AuthModel.findOne({ email }).exec();
      // CHECKING PASSWORD
      const hashedToken = user?.password;
      // DECRYPTING PASSWORD
      const decryptedPassword = jwt.verify(
        hashedToken,
        process.env.PRIVATE_KEY
      );

      // CHECKING PASSWORD WITH DECRYPTED
      if (decryptedPassword.password === password) {
        // CREATING TOKEN FOR LOGIN
        const token = jwt.sign(
          { name: user?.name, email: user?.email },
          process.env.PRIVATE_KEY
        );
        res.status(200).json({
          message: "Successfully logged in",
          id: user?.id,
          name: user?.name,
          email: user?.email,
          token,
        });
        return;
      }
      throw new Error("Invalid credentials");
    } catch (err) {
      res.status(403).json({ message: "Invalid credentials" });
    }
  });

  // LISTENER FOR THE PORT
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
};

main().catch((err) => console.log(err));
