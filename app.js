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
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

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

// Ruta para iniciar sesión y obtener token JWT
app.post('/login', async (req, res) => {
    const { usuario, contrasena } = req.body;

    if (!usuario || !contrasena) {
        return res.status(400).json({ error: 'Falta usuario o contraseña' });
    }

    const connection = getDbConnection();

    try {
        const results = await new Promise((resolve, reject) => {
            connection.query('SELECT * FROM usuarios WHERE usuario = ?', [usuario], (error, results) => {
                if (error) reject(error);
                else resolve(results);
            });
        });

        if (!results || results.length === 0) {
            return res.status(401).json({ error: 'Usuario o contraseña inválidos' });
        }

        const usuarioDb = results[0];

        const isMatch = await bcrypt.compare(contrasena, usuarioDb.contrasena);

        if (!isMatch) {
            return res.status(401).json({ error: 'Usuario o contraseña inválidos' });
        }

        const accessToken = jwt.sign({ usuario: usuarioDb.usuario }, JWT_SECRET_KEY);
        delete usuarioDb.contrasena;
        res.json({ mensaje: 'Inicio de sesión exitoso', access_token: accessToken, usuario: usuarioDb });

    } catch (error) {
        console.error('Error en la consulta:', error.stack);
        res.status(500).json({ error: 'No se pudo conectar a la base de datos' });
    } finally {
        closeDbConnection(connection);
    }
});

// Ruta para agregar un nuevo producto
app.post('/addProducto', authenticateToken, (req, res) => {
    const { nombre_producto, categoria, unidad_medida, comentario } = req.body;

    if (!nombre_producto || !categoria || !unidad_medida) {
        return res.status(400).json({ error: 'Faltan campos obligatorios' });
    }

    const connection = getDbConnection();

    // Insertar el nuevo producto en la base de datos con fecha de ingreso automática
    const sql = 'INSERT INTO Productos (nombre_producto, categoria, unidad_medida, fecha_ingreso, comentario) VALUES (?, ?, ?, NOW(), ?)';
    const values = [nombre_producto, categoria, unidad_medida, comentario];

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

// Ruta para listar todos los productos (requiere autenticación)
app.get('/productos', authenticateToken, (req, res) => {
    const connection = getDbConnection();
    const { q } = req.query; // Obtener el parámetro de búsqueda desde la query string

    let sql = 'SELECT * FROM Productos';

    if (q) {
        sql += ' WHERE nombre_producto LIKE ?';
        connection.query(sql, [`%${q}%`], (error, results) => {
            if (error) {
                res.status(500).json({ error: 'No se pudo obtener la lista de productos' });
            } else {
                res.json(results);
            }
            closeDbConnection(connection);
        });
    } else {
        connection.query(sql, (error, results) => {
            if (error) {
                res.status(500).json({ error: 'No se pudo obtener la lista de productos' });
            } else {
                res.json(results);
            }
            closeDbConnection(connection);
        });
    }
});

// Ruta para actualizar un producto (requiere autenticación)
app.put('/productos/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { nombre_producto, categoria, unidad_medida, comentario } = req.body;

    if (!nombre_producto || !categoria || !unidad_medida) {
        return res.status(400).json({ error: 'Faltan campos obligatorios' });
    }

    const connection = getDbConnection();

    // Actualizar el producto en la base de datos
    const sql = 'UPDATE Productos SET nombre_producto = ?, categoria = ?, unidad_medida = ?, comentario = ? WHERE id_producto = ?';
    const values = [nombre_producto, categoria, unidad_medida, comentario, id];

    connection.query(sql, values, (error, results) => {
        if (error) {
            console.error('Error ejecutando la consulta:', error.stack);
            res.status(500).json({ error: 'No se pudo actualizar el producto' });
        } else {
            res.json({ mensaje: 'Producto actualizado exitosamente' });
        }
        closeDbConnection(connection);
    });
});

// Ruta para eliminar un producto (requiere autenticación)
app.delete('/productos/:id', authenticateToken, (req, res) => {
    const { id } = req.params;

    const connection = getDbConnection();

    // Eliminar el producto de la base de datos
    const sql = 'DELETE FROM Productos WHERE id_producto = ?';
    connection.query(sql, [id], (error, results) => {
        if (error) {
            console.error('Error ejecutando la consulta:', error.stack);
            res.status(500).json({ error: 'No se pudo eliminar el producto' });
        } else {
            res.json({ mensaje: 'Producto eliminado exitosamente' });
        }
        closeDbConnection(connection);
    });
});

// Ruta para agregar inventario
app.post('/addInventario', authenticateToken, (req, res) => {
    const { id_producto, cantidad, precio_unitario } = req.body;

    if (!id_producto || !cantidad || !precio_unitario) {
        return res.status(400).json({ error: 'Faltan campos obligatorios' });
    }

    const connection = getDbConnection();

    // Insertar el nuevo registro de inventario en la base de datos
    const sql = 'INSERT INTO Inventario (id_producto, cantidad, precio_unitario, fecha_actualizacion) VALUES (?, ?, ?, NOW())';
    const values = [id_producto, cantidad, precio_unitario];

    connection.query(sql, values, (error, results) => {
        if (error) {
            console.error('Error ejecutando la consulta:', error.stack);
            res.status(500).json({ error: 'No se pudo agregar el inventario' });
        } else {
            res.status(201).json({ mensaje: 'Inventario agregado exitosamente', id_inventario: results.insertId });
        }
        closeDbConnection(connection);
    });
});

// Ruta para obtener el inventario
app.get('/inventario', (req, res) => {
    const { q } = req.query;

    const connection = getDbConnection();
    let sql = `
        SELECT i.*, p.*
        FROM Inventario i
        JOIN Productos p ON i.id_producto = p.id_producto
    `;
    let values = [];

    if (q) {
        sql += ' WHERE p.nombre_producto LIKE ?';
        values.push(`%${q}%`);
    }

    connection.query(sql, values, (error, results) => {
        if (error) {
            console.error('Error ejecutando la consulta:', error.stack);
            res.status(500).json({ error: 'No se pudo obtener el inventario' });
        } else {
            res.json(results);
        }
        closeDbConnection(connection);
    });
});

// Ruta para eliminar inventario
app.delete('/inventario/:id_inventario', (req, res) => {
    const { id_inventario } = req.params;

    if (!id_inventario) {
        return res.status(400).json({ error: 'Falta el id_inventario' });
    }

    const connection = getDbConnection();

    const sql = 'DELETE FROM Inventario WHERE id_inventario = ?';
    const values = [id_inventario];

    connection.query(sql, values, (error, results) => {
        if (error) {
            console.error('Error ejecutando la consulta:', error.stack);
            res.status(500).json({ error: 'No se pudo eliminar el inventario' });
        } else if (results.affectedRows === 0) {
            res.status(404).json({ error: 'No se encontró el inventario con el id proporcionado' });
        } else {
            res.status(200).json({ mensaje: 'Inventario eliminado exitosamente' });
        }
        closeDbConnection(connection);
    });
});

// Ruta protegida que requiere token JWT para acceder
app.get('/recurso_protegido', authenticateToken, (req, res) => {
    res.json({ mensaje: 'Acceso permitido', usuario: req.user });
});

app.get('/', (req, res) => {
    res.send('Hello, World!');
});

const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Servidor corriendo en el puerto ${port}`);
});
