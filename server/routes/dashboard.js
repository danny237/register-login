const router = require("express").Router();
const pool = require("../dbtest");
const authorization = require("../middleware/authorization");

router.get("/", authorization, async (req, res) => {
  try {
    //req.user has payload after authorization
    const user = await pool.query("SELECT * FROM users WHERE user_id = $1", [
      req.user,
    ]);
    res.json(user.rows[0].user_id);
  } catch (error) {
    console.log(error.message);
    res.status(500).json("Server Error !");
  }
});

module.exports = router;
