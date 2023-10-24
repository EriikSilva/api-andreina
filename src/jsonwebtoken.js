const jwt = require('jsonwebtoken');
const segredo = 'seuSegredoSuperSecreto';

function middlewareAutenticacao(req, res, next) {

  const token = req.header('Authorization');

  if (!token) {
    return res.status(401).json({ error: 'Acesso não autorizado. Token ausente.' });
  }

  try {
    const payload = jwt.verify(token, segredo);
    req.usuarioAutenticado = payload;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Acesso não autorizado. Token inválido.' });
  }
}

module.exports = middlewareAutenticacao;