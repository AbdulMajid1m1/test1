import express from "express";
import Login from './Login.js';



const router = express.Router();



router.use('/', Login);


export default router;
