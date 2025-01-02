require('dotenv').config({ path: __dirname + '/.env' }); // 使用绝对路径加载 .env 文件
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// 从环境变量中获取密钥
const SECRET_KEY = process.env.SECRET_KEY;

console.log('SECRET_KEY:', SECRET_KEY); // 添加调试日志

if (!SECRET_KEY) {
  console.error('JWT SECRET_KEY is not set. This is insecure!');
  process.exit(1);
}

// 数据库连接配置
const db = mysql.createConnection({
  host: 'rm-cn-3mp40u7fw000omro.rwlb.rds.aliyuncs.com', // 替换为你的 RDS 实例的内网或外网地址
  user: 'y2012643671',                                 // 替换为你的数据库用户名
  password: 'Gyn050614',                               // 替换为你的数据库密码
  database: 'testwork'
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err.stack);
    return;
  }
  console.log('Connected to the database.');
});

// 测试路由
app.get('/api/test', (req, res) => {
  res.json({ message: 'Test route working!' });
});

// 注册新用户
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  // 验证昵称是否唯一
  const checkSql = 'SELECT * FROM users WHERE username = ?';
  db.query(checkSql, [username], async (err, results) => {
    if (err) throw err;
    if (results.length > 0) {
      return res.status(400).json({ message: '昵称已存在' });
    }

    // 加密密码
    const hashedPassword = await bcrypt.hash(password, 10);

    // 插入新用户
    const insertSql = 'INSERT INTO users (username, password, signature, progress_percentage, poetry_correct_count, unlocked_paintings, unlocked_endings) VALUES (?, ?, ?, ?, ?, ?, ?)';
    db.query(insertSql, [username, hashedPassword, "这个人很神秘，什么也没有留下", 0, 0, '', ''], (err, result) => {
      if (err) throw err;
      res.send({ message: '注册成功', id: result.insertId });
    });
  });
});

// 登录用户
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // 查询用户
  const sql = 'SELECT * FROM users WHERE username = ?';
  db.query(sql, [username], async (err, results) => {
    if (err) throw err;
    if (results.length === 0) {
      return res.status(400).json({ message: '用户名或密码错误' });
    }

    const user = results[0];

    // 验证密码
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: '用户名或密码错误' });
    }

    // 生成 JWT 访问令牌
    const accessToken = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '7d' });

    res.json({ message: '登录成功', token: accessToken, user: { id: user.id, username: user.username } });
  });
});

// 验证 JWT 中间件
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: '未找到授权令牌' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      console.error('JWT verification failed:', err.message); // 添加错误日志
      return res.status(403).json({ message: '无效的授权令牌' });
    }
    req.user = user;
    next();
  });
}

// 获取当前用户信息
app.get('/api/user', authenticateToken, (req, res) => {
  const userId = req.user.id;

  // 查询用户详细信息
  const sql = 'SELECT * FROM users WHERE id = ?';
  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error('Error selecting user info:', err);
      return res.status(500).json({ message: '内部服务器错误' });
    }

    if (results.length === 0) {
      console.error('User not found:', userId); // 添加日志
      return res.status(404).json({ message: '用户未找到' });
    }

    const user = results[0];

    // 根据答题正确数确定诗词大会称号
    let poetryTitle = '';
    if (user.poetry_correct_count < 5) {
      poetryTitle = '初学吟咏';
    } else if (user.poetry_correct_count >= 5 && user.poetry_correct_count < 10) {
      poetryTitle = '新刃发硎';
    } else if (user.poetry_correct_count >= 10 && user.poetry_correct_count < 15) {
      poetryTitle = '诗才横溢';
    } else if (user.poetry_correct_count >= 15 && user.poetry_correct_count < 20) {
      poetryTitle = '文采斐然';
    } else {
      poetryTitle = '诗仙词圣';
    }

    // 解锁的画作数量
    const unlockedPaintings = user.unlocked_paintings || '';

    // 解锁的结局数量
    const unlockedEndings = user.unlocked_endings || '';

    res.json({
      id: user.id,
      username: user.username,
      signature: user.signature,
      progressPercentage: parseFloat(user.progress_percentage),
      poetryCorrectCount: user.poetry_correct_count,
      poetryTitle,
      unlockedPaintingsCount: unlockedPaintings.split(',').filter(Boolean).length,
      unlockedEndingsCount: unlockedEndings.split(',').filter(Boolean).length,
      unlockedPaintings,
      unlockedEndings
    });
  });
});

// 更新诗歌正确计数
app.post('/api/update-poetry-correct-count', authenticateToken, (req, res) => {
  const { correctCount } = req.body;
  const userId = req.user.id;

  // 更新用户的诗歌正确计数
  const updateSql = 'UPDATE users SET poetry_correct_count = ? WHERE id = ?';
  db.query(updateSql, [correctCount, userId], (err, result) => {
    if (err) {
      console.error('Error updating poetry correct count:', err);
      return res.status(500).json({ message: '内部服务器错误' });
    }
    res.json({ message: '诗歌正确计数更新成功' });
  });
});

// 解锁画作
app.post('/api/unlock-painting', authenticateToken, (req, res) => {
  const { paintingTitle } = req.body;
  const userId = req.user.id;

  console.log('Unlocking painting for user ID:', userId, 'with painting title:', paintingTitle); // 添加日志

  // 查询用户已解锁的画作
  const selectSql = 'SELECT unlocked_paintings FROM users WHERE id = ?';
  db.query(selectSql, [userId], (err, results) => {
    if (err) {
      console.error('Error selecting unlocked paintings:', err);
      return res.status(500).json({ message: '内部服务器错误' });
    }

    if (results.length === 0) {
      console.error('User not found:', userId); // 添加日志
      return res.status(404).json({ message: '用户未找到' });
    }

    const unlockedPaintings = results[0].unlocked_paintings || '';

    const unlockedArray = unlockedPaintings.split(',').filter(Boolean);

    if (unlockedArray.includes(paintingTitle)) {
      console.log('Painting already unlocked:', paintingTitle); // 添加日志
      return res.json({ message: '该画作已经解锁' });
    }

    // 将新解锁的画作添加到已解锁画作列表
    unlockedArray.push(paintingTitle);
    const updatedPaintings = unlockedArray.join(',');

    // 更新用户的已解锁画作字段
    const updateSql = 'UPDATE users SET unlocked_paintings = ? WHERE id = ?';
    db.query(updateSql, [updatedPaintings, userId], (err, result) => {
      if (err) {
        console.error('Error updating unlocked paintings:', err);
        return res.status(500).json({ message: '内部服务器错误' });
      }
      console.log('Painting unlocked successfully:', paintingTitle); // 添加日志
      res.json({ message: '画作解锁成功' });
    });
  });
});

// 解锁结局
app.post('/api/unlock-ending', authenticateToken, (req, res) => {
  const { endingTitle } = req.body;
  const userId = req.user.id;

  console.log('Unlocking ending for user ID:', userId, 'with ending title:', endingTitle); // 添加日志

  // 查询用户已解锁的结局
  const selectSql = 'SELECT unlocked_endings FROM users WHERE id = ?';
  db.query(selectSql, [userId], (err, results) => {
    if (err) {
      console.error('Error selecting unlocked endings:', err);
      return res.status(500).json({ message: '内部服务器错误' });
    }

    if (results.length === 0) {
      console.error('User not found:', userId); // 添加日志
      return res.status(404).json({ message: '用户未找到' });
    }

    const unlockedEndings = results[0].unlocked_endings || '';

    const unlockedArray = unlockedEndings.split(',').filter(Boolean);

    if (unlockedArray.includes(endingTitle)) {
      console.log('Ending already unlocked:', endingTitle); // 添加日志
      return res.json({ message: '该结局已经解锁' });
    }

    // 将新解锁的结局添加到已解锁结局列表
    unlockedArray.push(endingTitle);
    const updatedEndings = unlockedArray.join(',');

    // 更新用户的已解锁结局字段
    const updateSql = 'UPDATE users SET unlocked_endings = ? WHERE id = ?';
    db.query(updateSql, [updatedEndings, userId], (err, result) => {
      if (err) {
        console.error('Error updating unlocked endings:', err);
        return res.status(500).json({ message: '内部服务器错误' });
      }
      console.log('Ending unlocked successfully:', endingTitle); // 添加日志
      res.json({ message: '结局解锁成功' });
    });
  });
});

// 更新用户个性签名
app.post('/api/update-signature', authenticateToken, (req, res) => {
  const { signature } = req.body;
  const userId = req.user.id;

  console.log('Updating signature for user ID:', userId, 'with signature:', signature); // 添加日志

  // 更新用户的个性签名
  const updateSql = 'UPDATE users SET signature = ? WHERE id = ?';
  db.query(updateSql, [signature, userId], (err, result) => {
    if (err) {
      console.error('Error updating signature:', err);
      return res.status(500).json({ message: '内部服务器错误' });
    }
    console.log('Signature updated successfully:', signature); // 添加日志
    res.json({ message: '个性签名更新成功' });
  });
});

// 更新进度百分比
app.post('/api/update-progress', authenticateToken, (req, res) => {
  const { progress_percentage } = req.body;
  const userId = req.user.id;

  console.log('Updating progress for user ID:', userId, 'with progress percentage:', progress_percentage); // 添加日志

  // 更新用户的进度百分比
  const updateSql = 'UPDATE users SET progress_percentage = ? WHERE id = ?';
  db.query(updateSql, [progress_percentage, userId], (err, result) => {
    if (err) {
      console.error('Error updating progress:', err);
      return res.status(500).json({ message: '内部服务器错误' });
    }
    console.log('Progress updated successfully for user ID:', userId); // 添加日志
    res.json({ message: '进度更新成功' });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});



