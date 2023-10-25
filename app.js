const express = require('express');
const bodyParser = require('body-parser');

const jwt = require('jsonwebtoken');
const cors = require('cors')

const app = express();
app.use(cors())
app.use(bodyParser.json());
const segredo = 'seuSegredoSuperSecreto';

const users = [
    { nome: 'admin', senha: 'senha123', email:'admin@admin.com', telefone:'', cargo:"QA"},
];


function middlewareLoginJWT(req, res, next) {
  const data = req.body;

  for (const user of users) {
    if (user.email === data.email && user.senha === data.senha) {
      const token = jwt.sign({ email: user.email }, segredo);

      req.token = token;
      return next();
    }
  }

  res.status(401).json({ error: 'Token Ausente' });
}

const middlewareAutenticacao = require("./src/jsonwebtoken")


app.get('/api/users', (req, res) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).json({ error: 'Token Ausente' });
      }

      jwt.verify(token, segredo, (err, decoded) => {
        if (err) {
          return res.status(401).json({ error: 'Token Inválido' });
        }
      
        res.json(users);
      });

  
});

app.post('/api/register',(req, res) => {
    const data = req.body;

    const token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({ error: 'Token Ausente' });
      }

    
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

    if(data.telefone.length > 0 && data.telefone.length !== 11){
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

    jwt.verify(token, segredo, (err, decoded) => {
        if (err) {
          return res.status(401).json({ error: 'Token Inválido' });
        }
    
    
        const newUser = { nome: data.nome, email:data.email, senha:data.senha, telefone:data.telefone, cargo:data.cargo};
        users.push(newUser);
        res.status(201).json({ message: 'Usuário registrado com sucesso' });
      });

});

app.post('/api/login', (req, res) => {
    const data = req.body;

    if (!data.email || !data.senha) {
        return res.status(400).json({ error: 'Campos "nome" e "senha" são obrigatórios' });
    }

    for (const user of users) {
        if (user.email === data.email && user.senha === data.senha) {
            return res.status(200).json({ 
                message: 'Login bem-sucedido',
                token: globalToken
            });
        }
    }

    res.status(401).json({ error: 'Credenciais inválidas' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor em execução na porta ${PORT}`);
});
