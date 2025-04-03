module.exports = (req, res, next) => {
    const appKey = req.headers['x-app-key'];
    if (!appKey || appKey !== process.env.APP_KEY) {
      return res.status(403).json({ message: 'Chave de aplicação inválida' });
    }
    next();
  };
  