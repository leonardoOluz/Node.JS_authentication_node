/*  Imports das lib e frameworks */
import mongoose from "mongoose";
import dotenv from 'dotenv';
/* Credencials */
dotenv.config();
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@clusterleoluz.zoaawnu.mongodb.net/API_Auth?`)
const db = mongoose.connection;

export default db;