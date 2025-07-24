const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });
const PORT = 5000;
const JWT_SECRET = 'your_jwt_secret';

app.use(cors());
app.use(express.json());

mongoose.connect('mongodb+srv://mrbu_rger:Nikita_24042006@server.zescnvf.mongodb.net/chat', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB подключён'))
  .catch(err => console.error('Ошибка MongoDB:', err.message));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  online: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now }
});

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  recipient: { type: String, required: true },
  content: { type: String, required: true },
  type: { type: String, required: true },
  mimeType: { type: String },
  fileName: { type: String },
  timestamp: { type: Date, default: Date.now },
  read: { type: Boolean, default: false },
  deleted: { type: Boolean, default: false },
  edited: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

function isValidBase64(str) { try { return btoa(atob(str)) === str; } catch (err) { return false; } }

app.get('/health', (req, res) => res.json({ status: 'running', mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' }));

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Логин и пароль обязательны' });
  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ message: 'Пользователь уже существует' });
    const hashedPassword = await bcrypt.hash(password, 10);
    await new User({ username, password: hashedPassword }).save();
    res.status(201).json({ message: 'Регистрация успешна' });
  } catch (err) { res.status(500).json({ message: 'Ошибка сервера' }); }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'Логин и пароль обязательны' });
  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ message: 'Неверный логин или пароль' });
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    user.online = true; user.lastSeen = new Date(); await user.save();
    res.json({ username, token });
  } catch (err) { res.status(500).json({ message: 'Ошибка сервера' }); }
});

app.get('/api/check-auth', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Токен отсутствует' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ username: decoded.username });
    if (!user) return res.status(401).json({ message: 'Пользователь не найден' });
    res.json({ username: user.username });
  } catch (err) { res.status(401).json({ message: 'Недействительный токен' }); }
});

app.get('/api/users', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Токен отсутствует' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const users = await User.find({ username: { $ne: decoded.username } });
    const usersWithMessages = await Promise.all(users.map(async user => {
      const lastMessage = await Message.findOne({ $or: [{ sender: decoded.username, recipient: user.username }, { sender: user.username, recipient: decoded.username }] }).sort({ timestamp: -1 });
      const unread = await Message.countDocuments({ sender: user.username, recipient: decoded.username, read: false, deleted: false });
      return { username: user.username, online: user.online, lastSeen: user.lastSeen, lastMessage, unread };
    }));
    res.json(usersWithMessages);
  } catch (err) { res.status(500).json({ message: 'Ошибка сервера' }); }
});

app.get('/api/messages/:recipient', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1], { recipient } = req.params;
  if (!token) return res.status(401).json({ message: 'Токен отсутствует' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const messages = await Message.find({ $or: [{ sender: decoded.username, recipient }, { sender: recipient, recipient: decoded.username }] }).sort({ timestamp: 1 });
    res.json(messages);
  } catch (err) { res.status(500).json({ message: 'Ошибка сервера' }); }
});

app.post('/api/message', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1], { recipient, content, type, mimeType, fileName } = req.body;
  if (!token || !recipient || !content || !type) return res.status(401).json({ message: 'Токен, получатель, содержимое и тип обязательны' });
  if (type !== 'text' && (!mimeType || content.length > 7*1024*1024 || !isValidBase64(content))) return res.status(400).json({ message: 'Недопустимый файл или размер >5MB' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const message = new Message({ sender: decoded.username, recipient, content, type, mimeType, fileName });
    await message.save();
    io.to(recipient).emit('new-message', message); io.to(decoded.username).emit('new-message', message);
    res.json(message);
  } catch (err) { res.status(500).json({ message: 'Ошибка сервера' }); }
});

app.post('/api/messages/:messageId/read', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1], { messageId } = req.params;
  if (!token || !messageId) return res.status(401).json({ message: 'Токен и messageId обязательны' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const message = await Message.findOne({ _id: messageId, recipient: decoded.username });
    if (!message) return res.status(404).json({ message: 'Сообщение не найдено' });
    if (message.read) return res.status(400).json({ message: 'Сообщение уже прочитано' });
    message.read = true; await message.save();
    io.to(message.sender).emit('message-read', { messageId, sender: message.sender, recipient: message.recipient });
    res.json({ message: 'Сообщение отмечено прочитанным' });
  } catch (err) { res.status(500).json({ message: 'Ошибка сервера' }); }
});

app.post('/api/messages/:messageId/delete', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1], { messageId } = req.params;
  if (!token || !messageId) return res.status(401).json({ message: 'Токен и messageId обязательны' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const message = await Message.findOne({ _id: messageId, sender: decoded.username });
    if (!message) return res.status(404).json({ message: 'Сообщение не найдено или вы не отправитель' });
    if (message.deleted) return res.status(400).json({ message: 'Сообщение уже удалено' });
    message.deleted = true; await message.save();
    io.to(message.recipient).emit('message-deleted', { messageId, sender: message.sender, recipient: message.recipient });
    io.to(message.sender).emit('message-deleted', { messageId, sender: message.sender, recipient: message.recipient });
    res.json({ message: 'Сообщение удалено' });
  } catch (err) { res.status(500).json({ message: 'Ошибка сервера' }); }
});

app.post('/api/messages/:messageId/edit', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1], { messageId } = req.params, { content, type, mimeType, fileName } = req.body;
  if (!token || !messageId || !content || !type) return res.status(401).json({ message: 'Токен, messageId, содержимое и тип обязательны' });
  if (type !== 'text' && (!mimeType || content.length > 7*1024*1024 || !isValidBase64(content))) return res.status(400).json({ message: 'Недопустимый файл или размер >5MB' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const message = await Message.findOne({ _id: messageId, sender: decoded.username });
    if (!message) return res.status(404).json({ message: 'Сообщение не найдено или вы не отправитель' });
    if (message.deleted) return res.status(400).json({ message: 'Нельзя редактировать удалённое сообщение' });
    message.content = content; message.type = type; message.mimeType = mimeType; message.fileName = fileName; message.edited = true; await message.save();
    io.to(message.recipient).emit('message-edited', { messageId, sender: message.sender, recipient: message.recipient, content, type, mimeType, fileName, edited: true });
    io.to(message.sender).emit('message-edited', { messageId, sender: message.sender, recipient: message.recipient, content, type, mimeType, fileName, edited: true });
    res.json({ message: 'Сообщение отредактировано' });
  } catch (err) { res.status(500).json({ message: 'Ошибка сервера' }); }
});

io.on('connection', socket => {
  socket.on('authenticate', async token => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findOne({ username: decoded.username });
      if (!user) { socket.emit('error', { message: 'Пользователь не найден' }); socket.disconnect(); return; }
      socket.username = decoded.username; socket.join(decoded.username);
      user.online = true; user.lastSeen = new Date(); await user.save();
      io.emit('user-status', { username: decoded.username, online: true, lastSeen: user.lastSeen });
    } catch (err) { socket.emit('error', { message: 'Недействительный токен' }); socket.disconnect(); }
  });
  socket.on('send-message', async ({ recipient, content, type, mimeType, fileName }) => {
    if (!socket.username || !recipient || !content || !type) { socket.emit('error', { message: 'Не авторизован или отсутствуют данные' }); return; }
    if (type !== 'text' && (!mimeType || content.length > 7*1024*1024 || !isValidBase64(content))) { socket.emit('error', { message: 'Недопустимый файл или размер >5MB' }); return; }
    try {
      const message = new Message({ sender: socket.username, recipient, content, type, mimeType, fileName });
      await message.save();
      io.to(recipient).emit('new-message', message); io.to(socket.username).emit('new-message', message);
    } catch (err) { socket.emit('error', { message: 'Ошибка сервера' }); }
  });
  socket.on('typing', ({ sender, recipient }) => { if (sender && recipient) io.to(recipient).emit('typing', { sender, recipient }); });
  socket.on('read-message', async ({ messageId }) => {
    if (!socket.username || !messageId) { socket.emit('error', { message: 'Не авторизован или отсутствует messageId' }); return; }
    try {
      const message = await Message.findOne({ _id: messageId, recipient: socket.username });
      if (!message) { socket.emit('error', { message: 'Сообщение не найдено' }); return; }
      if (!message.read) { message.read = true; await message.save(); io.to(message.sender).emit('message-read', { messageId, sender: message.sender, recipient: message.recipient }); }
    } catch (err) { socket.emit('error', { message: 'Ошибка сервера' }); }
  });
  socket.on('delete-message', async ({ messageId }) => {
    if (!socket.username || !messageId) { socket.emit('error', { message: 'Не авторизован или отсутствует messageId' }); return; }
    try {
      const message = await Message.findOne({ _id: messageId, sender: socket.username });
      if (!message) { socket.emit('error', { message: 'Сообщение не найдено или вы не отправитель' }); return; }
      if (message.deleted) { socket.emit('error', { message: 'Сообщение уже удалено' }); return; }
      message.deleted = true; await message.save();
      io.to(message.recipient).emit('message-deleted', { messageId, sender: message.sender, recipient: message.recipient });
      io.to(message.sender).emit('message-deleted', { messageId, sender: message.sender, recipient: message.recipient });
    } catch (err) { socket.emit('error', { message: 'Ошибка сервера' }); }
  });
  socket.on('edit-message', async ({ messageId, content, type, mimeType, fileName }) => {
    if (!socket.username || !messageId || !content || !type) { socket.emit('error', { message: 'Не авторизован или отсутствуют данные' }); return; }
    if (type !== 'text' && (!mimeType || content.length > 7*1024*1024 || !isValidBase64(content))) { socket.emit('error', { message: 'Недопустимый файл или размер >5MB' }); return; }
    try {
      const message = await Message.findOne({ _id: messageId, sender: socket.username });
      if (!message) { socket.emit('error', { message: 'Сообщение не найдено или вы не отправитель' }); return; }
      if (message.deleted) { socket.emit('error', { message: 'Нельзя редактировать удалённое сообщение' }); return; }
      message.content = content; message.type = type; message.mimeType = mimeType; message.fileName = fileName; message.edited = true; await message.save();
      io.to(message.recipient).emit('message-edited', { messageId, sender: message.sender, recipient: message.recipient, content, type, mimeType, fileName, edited: true });
      io.to(message.sender).emit('message-edited', { messageId, sender: message.sender, recipient: message.recipient, content, type, mimeType, fileName, edited: true });
    } catch (err) { socket.emit('error', { message: 'Ошибка сервера' }); }
  });
  socket.on('disconnect', async () => {
    if (socket.username) {
      try {
        const user = await User.findOne({ username: socket.username });
        if (user) { user.online = false; user.lastSeen = new Date(); await user.save(); io.emit('user-status', { username: socket.username, online: false, lastSeen: user.lastSeen }); }
      } catch (err) {}
    }
  });
});

server.listen(PORT, () => console.log(`Сервер запущен на http://localhost:${PORT}`));