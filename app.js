/* Imports dos framework e lib em uso no projeto */
import dotenv from 'dotenv';
import express, { response } from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import db from './src/config/dbConnect.js';
import User from './src/model/User.js';

// criando variaveis 

const port = process.env.PORT || 3000;
const app = express();
app.use(express.json());

// conexão com o banco de dados

db.on('erro', console.log.bind(console, 'erro de conexão'))
db.once('open', () => {
    console.log('Banco de dados conectado com sucesso!')
})
// Open Route - Public Route
app.get('/', async (req, res) => {
    res.status(200).json({ message: "Bem vindo a nossa API!" })
})
// Private Route
app.get('/user/:id', checkToken, async(req, res) => {
    const id = req.params.id;

    // check if user exists
    const user = await User.findById(id,'-password');
    
    if(!user){
        res.status(404).json({msg: 'Usuario não encontrado!'})
    }
    res.status(200).json({user})

})
function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token){
        return res.status(401).json({msg: 'Acesso negado!'})
    }

    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()
    } catch (error) {
        res.status(400).json({msg: 'Token inválido!'})
    }

}
// Register User
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;
    // validations
    if (!name) {
        return res.status(422).json({ msg: `o nome é obrigatório!` })
    }
    if (!email) {
        res.status(422).json({ msg: `o email é obrigatório!` })
    }
    if (!password) {
        res.status(422).json({ msg: `A senha é obrigatório!` })
    }
    if (password !== confirmPassword) {
        res.status(422).json({ msg: `A senhas não conferem!` })
    }
    // check if use exists
    const userExists = await User.findOne({ email: email })

    if (userExists) {
        res.status(422).json({ msg: `Por favor, utilize outro email!` })
    }
    // create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {

        await user.save()
        res.status(201).json({ msg: `Usuario cadastrado com sucesso!` })

    } catch (error) {
        console.log(error)
        res.status(500).json({ msg: `Aconteceu um erro no servidor, tente novamente mais tarde!` })
    }

})
// Login user
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body

    // validations
    if (!email) {
        res.status(422).json({ msg: `o email é obrigatório!` })
    }
    if (!password) {
        res.status(422).json({ msg: `A senha é obrigatório!` })
    }
    // check if user exists
    const user = await User.findOne({ email: email })

    if (!user) {
        res.status(404).json({ msg: `Usuario não encontrado!` })
    }
    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        res.status(422).json({ msg: `Senha inválida!` })
    }
    try {

        const secret = process.env.SECRET;
        const token = jwt.sign(
            {
                id: user._id,
            }, 
            secret,
        )
        res.status(200).json({msg: 'Autenticação realizada com sucesso', token})


    } catch (error) {
        console.log(error)
        res.status(500).json({ msg: `Aconteceu um erro no servidor, tente novamente mais tarde!` })
    }

})
app.listen(port, () => {
    console.log(`Servidor escutando na porta http://localhost:${port}`)
})