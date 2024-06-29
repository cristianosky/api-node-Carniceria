const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const { getDbConnection, closeDbConnection } = require('./db');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

// Middleware para verificar el token JWT
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Ruta para obtener todos los usuarios (requiere autenticación)
app.get('/usuarios', authenticateToken, (req, res) => {
    const connection = getDbConnection();

    connection.query('SELECT id, nombre, usuario, estado FROM usuarios', (error, results) => {
        if (error) {
            res.status(500).json({ error: 'No se pudo conectar a la base de datos' });
        } else {
            res.json(results);
        }
        closeDbConnection(connection);
    });
});

// Ruta para registrar un nuevo usuario
app.post('/registro', (req, res) => {
    const { nombre, usuario, contrasena, estado = 1 } = req.body;

    if (!nombre || !usuario || !contrasena) {
        return res.status(400).json({ error: 'Faltan campos obligatorios' });
    }

    const connection = getDbConnection();

    // Verificar si el usuario ya existe
    connection.query('SELECT * FROM usuarios WHERE usuario = ?', [usuario], (error, results) => {
        if (error) {
            res.status(500).json({ error: 'No se pudo registrar el usuario' });
        } else if (results.length > 0) {
            res.status(400).json({ error: 'El nombre de usuario ya está en uso' });
        } else {
            const contrasenaHasheada = bcrypt.hashSync(contrasena, 10);

            const query = 'INSERT INTO usuarios (nombre, usuario, contrasena, estado) VALUES (?, ?, ?, ?)';
            connection.query(query, [nombre, usuario, contrasenaHasheada, estado], (error, results) => {
                if (error) {
                    res.status(500).json({ error: 'No se pudo registrar el usuario' });
                } else {
                    res.status(201).json({ mensaje: 'Usuario registrado correctamente' });
                }
                closeDbConnection(connection);
            });
        }
    });
});

// Ruta para realizar el inicio de sesión y obtener token JWT
app.post('/login', (req, res) => {
    const { usuario, contrasena } = req.body;

    if (!usuario || !contrasena) {
        return res.status(400).json({ error: 'Falta usuario o contraseña' });
    }

    const connection = getDbConnection();

    connection.query('SELECT * FROM usuarios WHERE usuario = ?', [usuario], (error, results) => {
        if (error || results.length === 0) {
            res.status(500).json({ error: 'No se pudo conectar a la base de datos' });
        } else {
            const usuarioDb = results[0];

            if (!bcrypt.compareSync(contrasena, usuarioDb.contrasena)) {
                res.status(401).json({ error: 'Usuario o contraseña inválidos' });
            } else {
                const accessToken = jwt.sign({ usuario: usuarioDb.usuario }, JWT_SECRET_KEY);
                delete usuarioDb.contrasena;
                res.json({ mensaje: 'Inicio de sesión exitoso', access_token: accessToken, usuario: usuarioDb });
            }
        }
        closeDbConnection(connection);
    });
});

// Ruta protegida que requiere token JWT para acceder
app.get('/recurso_protegido', authenticateToken, (req, res) => {
    res.json({ mensaje: 'Acceso permitido', usuario: req.user });
});

app.post('/addproductos', authenticateToken, (req, res) => {
    const { nombre_producto, categoria, unidad_medida, precio_unitario, comentario } = req.body;

    if (!nombre_producto || !categoria || !unidad_medida || !precio_unitario) {
        return res.status(400).json({ error: 'Faltan campos obligatorios' });
    }

    const connection = getDbConnection();

    // Insertar el nuevo producto en la base de datos con fecha de ingreso automática
    const sql = 'INSERT INTO Productos (nombre_producto, categoria, unidad_medida, precio_unitario, fecha_ingreso, comentario) VALUES (?, ?, ?, ?, NOW(), ?)';
    const values = [nombre_producto, categoria, unidad_medida, precio_unitario, comentario];

    connection.query(sql, values, (error, results) => {
        if (error) {
            console.error('Error ejecutando la consulta:', error.stack);
            res.status(500).json({ error: 'No se pudo agregar el producto' });
        } else {
            res.status(201).json({ mensaje: 'Producto agregado exitosamente', id_producto: results.insertId });
        }
        closeDbConnection(connection);
    });
});

app.get('/', (req, res) => {
    res.send('Hello, World!');
});

const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Servidor corriendo en el puerto ${port}`);
});
