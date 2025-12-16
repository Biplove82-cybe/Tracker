// Load environment variables first
const dotenv = require("dotenv");
dotenv.config({ path: './.env' });

const express = require("express");
const connectDB = require("./Config/dbConfig");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");

const routes = require("./routes/routes");
const projectRoutes = require("./routes/Project/project");
const userRoutes =require("./routes/User")

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const PORT = process.env.PORT || 5000;
const db = process.env.MONGO_URI;

// 🔹 Connect to MongoDB
connectDB(db);

// 🔹 Routes
app.use("/v1", routes);
app.use("/v1/project", projectRoutes);
app.use("/v1/user",userRoutes)

// 🔹 Server Listen
app.listen(PORT, () => {
  console.log(`🚀 Server listening at http://localhost:${PORT}`);
});
