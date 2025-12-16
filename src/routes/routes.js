const router = require("express").Router();
const jwtMW = require("../Middleware/Auth/auth");

// const { userRegister, login, getuser } = require("../controllers/user/user");
const { createBDlead, getAllLeads, updateLeadStatus }=require("../controllers/BD-lead/lead");





// //user
// router.post("/user-register",userRegister)
// router.post("/login",login)
// router.get("/get-user",getuser);

//bd
router.post("/create-lead",jwtMW.authentication,
  jwtMW.authorization,createBDlead)

  router.get("/get-all-lead",getAllLeads);

  router.put("/update-lead/:_id/status"
  ,updateLeadStatus)
module.exports = router;