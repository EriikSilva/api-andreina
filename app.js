const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors')

const app = express();
app.use(cors())
app.use(bodyParser.json());

const users = [
    { nome: 'usuarioTeste', senha: 'senhaTeste', email:'emailTeste' },
];

app.get('/api/users', (req, res) => {
    res.json(users);
});


// Rota para criar um novo usuário (registro)
app.post('/api/register', (req, res) => {
    const data = req.body;
    if (data.nome == "") {
        return res.status(400).json({ error: 'Campo nome não pode ser vazio' });
    }

    if (data.nome.length < 3) {
        return res.status(400).json({ error: 'Campo nome não pode ser menor que 3 caracteres' });
    }

    if (data.nome.length > 80) {
        return res.status(400).json({ error: 'Campo nome não pode ser maior que 80 caracteres' });
    }
    const regexEmail = /^[\w\.-]+@[\w\.-]+\.\w+$/;

    if(!regexEmail.test(data.email)){
        return res.status(400).json({ error: 'Campo email inválido' });
    }

    if (users.some(user => user.email === data.email)) {
      return res.status(400).json({ error: 'Endereço de e-mail já existe' });
    }

    const letrasRegex = /[a-zA-Z]/.test(data.senha);
    const numerosRegex = /\d/.test(data.senha);
    
      
    if(!data.senha || data.senha < 6){
        return res.status(400).json({ error: 'Campo senha não pode ser vazio ou menor que 6 caracteres' });
    }

    if(!letrasRegex || !numerosRegex){
      return res.status(400).json({ error: 'A senha deve conter letra(s) e numero(s)' });
    }

    if(!data.telefone){
        return res.status(400).json({ error: 'Campo telefone não pode ser vazio' });
    }

    if(data.telefone < 11){
        return res.status(400).json({ error: 'Campo telefone não pode ser menor que 11 caracteres' });
    }

    if(isNaN(data.telefone)){
        return res.status(400).json({ error: 'Campo telefone não pode conter letras ou caracteres especiais' });
    }

    if(!data.cargo){
        return res.status(400).json({ error: 'Campo role não pode ser vazio' });
    }

    if(data.cargo !== "QA" && data.cargo !== "DEV" && data.cargo !== "PO"){
        return res.status(400).json({ error: 'Campo cargo inválido' });
    }
    
    const newUser = { nome: data.nome, senha: data.senha, email:data.email, senha:data.senha, telefone:data.telefone, cargo:data.cargo};
    users.push(newUser);
    res.status(201).json({ message: 'Usuário registrado com sucesso' });
});

app.post('/api/login', (req, res) => {
    const data = req.body;
    if (!data.nome || !data.senha) {
        return res.status(400).json({ error: 'Campos "nome" e "senha" são obrigatórios' });
    }

    for (const user of users) {
        if (user.nome === data.nome && user.senha === data.senha) {
            return res.status(200).json({ message: 'Login bem-sucedido' });
        }
    }

    res.status(401).json({ error: 'Credenciais inválidas' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor em execução na porta ${PORT}`);
});
