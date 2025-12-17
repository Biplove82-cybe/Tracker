const router = require("express").Router();
const jwtMW = require("../Middleware/Auth/auth");
const { userRegister, getUser, login, refreshToken, logout } =require("../controllers/user/userController");

router.post("/user-register",userRegister);
router.get("/get-user",getUser);
router.post("/login",login);
router.post("/refreshToken",refreshToken);
router.post("/logout",logout);

module.exports=router