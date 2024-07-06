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

        delete usuarioDb.contrasena;
        const accessToken = jwt.sign({ usuario: usuarioDb }, JWT_SECRET_KEY);
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
app.get('/inventario', authenticateToken, (req, res) => {
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
app.delete('/inventario/:id_inventario', authenticateToken, (req, res) => {
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

// Ruta para agregar el detalle de una venta
app.post('/addDetalleVenta', authenticateToken, (req, res) => {
    const { id_venta, id_producto, cantidad, precio_unitario, id_inventario } = req.body;

    if (!id_producto || !cantidad || !precio_unitario || !id_inventario) {
        return res.status(400).json({ error: 'Faltan campos obligatorios' });
    }

    const connection = getDbConnection();

    // Iniciar una transacción
    connection.beginTransaction(async (err) => {
        if (err) {
            return res.status(500).json({ error: 'No se pudo iniciar la transacción' });
        }

        try {
            let ventaId = id_venta;
            let ventaCreada = null;

            // validar si la cantidad solicitada está disponible en el inventario
            const inventarioSql = 'SELECT cantidad FROM Inventario WHERE id_inventario = ?';
            const inventarioResult = await new Promise((resolve, reject) => {
                connection.query(inventarioSql, [id_inventario], (error, results) => {
                    if (error) reject(error);
                    else resolve(results);
                });
            });

            if (inventarioResult.length === 0) {
                return connection.rollback(() => {
                    res.status(404).json({ error: 'No se encontró el inventario' });
                });
            }

            const cantidadDisponible = inventarioResult[0].cantidad;

            if (cantidadDisponible < cantidad) {
                return connection.rollback(() => {
                    res.status(400).json({ error: 'La cantidad solicitada no está disponible en el inventario' });
                });
            }
            

            // Si no se proporciona un id_venta, se crea una nueva venta
            if (!ventaId) {
                // Obtener id_usuario del token
                const decodedToken = jwt.verify(req.headers['authorization'].split(' ')[1], JWT_SECRET_KEY);
                const id_usuario = decodedToken.usuario.id;
                const total_venta = cantidad * precio_unitario;
                const pagada = false;

                // Insertar nueva venta
                const ventaSql = 'INSERT INTO Ventas (id_usuario, fecha_venta, total_venta, pagada) VALUES (?, NOW(), ?, ?)';
                const ventaValues = [id_usuario, total_venta, pagada];
                const ventaResult = await new Promise((resolve, reject) => {
                    connection.query(ventaSql, ventaValues, (error, results) => {
                        if (error) reject(error);
                        else resolve(results);
                    });
                });

                ventaId = ventaResult.insertId;

                ventaCreada = { id_venta: ventaId, id_usuario, fecha_venta: new Date(), total_venta, pagada };
            }

            // Insertar el nuevo detalle de venta
            const subtotal = cantidad * precio_unitario;
            const detalleSql = 'INSERT INTO DetalleVentas (id_venta, id_producto, cantidad, precio_unitario, subtotal) VALUES (?, ?, ?, ?, ?)';
            const detalleValues = [ventaId, id_producto, cantidad, precio_unitario, subtotal];
            const detalleResult = await new Promise((resolve, reject) => {
                connection.query(detalleSql, detalleValues, (error, results) => {
                    if (error) reject(error);
                    else resolve(results);
                });
            });

            // Actualizar la cantidad en el inventario
            const updateInventarioSql = 'UPDATE Inventario SET cantidad = cantidad - ? WHERE id_inventario = ?';
            const updateInventarioValues = [cantidad, id_inventario];
            await new Promise((resolve, reject) => {
                connection.query(updateInventarioSql, updateInventarioValues, (error, results) => {
                    if (error) reject(error);
                    else resolve(results);
                });
            });

            // Si la venta no está pagada, actualizar el total de la venta
            if (!ventaCreada) {
                const updateVentaSql = 'UPDATE Ventas SET total_venta = total_venta + ? WHERE id_venta = ?';
                const updateVentaValues = [subtotal, ventaId];
                await new Promise((resolve, reject) => {
                    connection.query(updateVentaSql, updateVentaValues, (error, results) => {
                        if (error) reject(error);
                        else resolve(results);
                    });
                });
            }


            // Confirmar la transacción
            connection.commit((err) => {
                if (err) {
                    return connection.rollback(() => {
                        res.status(500).json({ error: 'No se pudo completar la transacción' });
                    });
                }

                if(ventaCreada) {
                    res.status(201).json({ mensaje: 'Detalle de venta agregado exitosamente', venta: ventaCreada, id_detalle_venta: detalleResult.insertId });
                } else {
                    res.status(201).json({ mensaje: 'Detalle de venta agregado exitosamente', id_detalle_venta: detalleResult.insertId });
                }
            });
        } catch (error) {
            console.error('Error en la transacción:', error.stack);
            connection.rollback(() => {
                res.status(500).json({ error: 'No se pudo agregar el detalle de venta' });
            });
        } finally {
            closeDbConnection(connection);
        }
    });
});

// Ruta para obtener los detalles de una venta por id_venta
app.get('/detalleVenta/:id_venta', authenticateToken, (req, res) => {
    const { id_venta } = req.params;

    if (!id_venta) {
        return res.status(400).json({ error: 'Faltan campos obligatorios' });
    }

    const connection = getDbConnection();

    const detalleVentaSql = `
        SELECT dv.id_detalle, dv.id_venta, dv.id_producto, dv.cantidad, dv.precio_unitario, p.nombre_producto, dv.subtotal, p.unidad_medida
        FROM DetalleVentas dv
        JOIN Productos p ON dv.id_producto = p.id_producto
        WHERE dv.id_venta = ?`;

    connection.query(detalleVentaSql, [id_venta], (error, results) => {
        if (error) {
            console.error('Error al obtener los detalles de la venta:', error.stack);
            return res.status(500).json({ error: 'No se pudo obtener los detalles de la venta' });
        }

        res.status(200).json(results);
    });

    closeDbConnection(connection);
});

// Ruta para eliminar un detalle de venta por id_detalle_venta
app.delete('/detalleVenta/:id_detalle_venta', authenticateToken, (req, res) => {
    const { id_detalle_venta } = req.params;

    if (!id_detalle_venta) {
        return res.status(400).json({ error: 'Faltan campos obligatorios' });
    }

    const connection = getDbConnection();

    connection.beginTransaction(async (err) => {
        if (err) {
            return res.status(500).json({ error: 'No se pudo iniciar la transacción' });
        }

        try {
            // Obtener el detalle de venta antes de eliminarlo
            const detalleSql = 'SELECT id_venta, id_producto, cantidad FROM DetalleVentas WHERE id_detalle = ?';
            const detalleValues = [id_detalle_venta];
            const detalleResult = await new Promise((resolve, reject) => {
                connection.query(detalleSql, detalleValues, (error, results) => {
                    if (error) reject(error);
                    else resolve(results);
                });
            });

            if (detalleResult.length === 0) {
                return connection.rollback(() => {
                    res.status(404).json({ error: 'No se encontró el detalle de venta' });
                });
            }

            const { id_venta, id_producto, cantidad } = detalleResult[0];

            // Eliminar el detalle de venta
            const deleteDetalleSql = 'DELETE FROM DetalleVentas WHERE id_detalle = ?';
            await new Promise((resolve, reject) => {
                connection.query(deleteDetalleSql, [id_detalle_venta], (error, results) => {
                    if (error) reject(error);
                    else resolve(results);
                });
            });

            // Revertir la cantidad en el inventario
            const updateInventarioSql = 'UPDATE Inventario SET cantidad = cantidad + ? WHERE id_producto = ?';
            const updateInventarioValues = [cantidad, id_producto];
            await new Promise((resolve, reject) => {
                connection.query(updateInventarioSql, updateInventarioValues, (error, results) => {
                    if (error) reject(error);
                    else resolve(results);
                });
            });

            // Si la venta no tiene más detalles, eliminar la venta
            const detallesVentaSql = 'SELECT * FROM DetalleVentas WHERE id_venta = ?';
            const detallesVentaValues = [id_venta];
            const detallesVentaResult = await new Promise((resolve, reject) => {
                connection.query(detallesVentaSql, detallesVentaValues, (error, results) => {
                    if (error) reject(error);
                    else resolve(results);
                });
            });

            let deleteVenta = false;

            if (detallesVentaResult.length === 0) {
                const deleteVentaSql = 'DELETE FROM Ventas WHERE id_venta = ?';
                await new Promise((resolve, reject) => {
                    connection.query(deleteVentaSql, [id_venta], (error, results) => {
                        if (error) reject(error);
                        else {
                            deleteVenta = true;
                            resolve(results);
                        };
                    });
                });
            }else{
                // Actualizar el total de la venta
                const totalVentaSql = 'SELECT SUM(subtotal) AS total_venta FROM DetalleVentas WHERE id_venta = ?';
                const totalVentaValues = [id_venta];
                const totalVentaResult = await new Promise((resolve, reject) => {
                    connection.query(totalVentaSql, totalVentaValues, (error, results) => {
                        if (error) reject(error);
                        else resolve(results);
                    });
                });

                const total_venta = totalVentaResult[0].total_venta;

                const updateVentaSql = 'UPDATE Ventas SET total_venta = ? WHERE id_venta = ?';
                const updateVentaValues = [total_venta, id_venta];
                await new Promise((resolve, reject) => {
                    connection.query(updateVentaSql, updateVentaValues, (error, results) => {
                        if (error) reject(error);
                        else resolve(results);
                    });
                });

            }

            // Confirmar la transacción
            connection.commit((err) => {
                if (err) {
                    return connection.rollback(() => {
                        res.status(500).json({ error: 'No se pudo completar la transacción' });
                    });
                }

                res.status(200).json({ mensaje: 'Detalle de venta eliminado exitosamente', deleteVenta });
            });
        } catch (error) {
            console.error('Error en la transacción:', error.stack);
            connection.rollback(() => {
                res.status(500).json({ error: 'No se pudo eliminar el detalle de venta' });
            });
        } finally {
            closeDbConnection(connection);
        }
    });
});

// Ruta para pagar una venta
app.put('/pagarVenta/:id_venta', authenticateToken, async (req, res) => {
    const id_venta = req.params.id_venta;

    const connection = getDbConnection();

    try {
        // Verificar si la venta existe
        const checkVentaSql = 'SELECT * FROM Ventas WHERE id_venta = ?';
        const [ventaResult] = await new Promise((resolve, reject) => {
            connection.query(checkVentaSql, [id_venta], (error, results) => {
                if (error) reject(error);
                else resolve(results);
            });
        });

        if (!ventaResult || ventaResult.length === 0) {
            return res.status(404).json({ error: 'La venta no existe' });
        }

        // Verificar si la venta ya está pagada
        if (ventaResult.pagada) {
            return res.status(400).json({ error: 'La venta ya ha sido pagada' });
        }

        // Marcar la venta como pagada
        const pagarVentaSql = 'UPDATE Ventas SET pagada = true WHERE id_venta = ?';
        await new Promise((resolve, reject) => {
            connection.query(pagarVentaSql, [id_venta], (error, results) => {
                if (error) reject(error);
                else resolve(results);
            });
        });

        // Confirmar la transacción
        connection.commit((err) => {
            if (err) {
                return connection.rollback(() => {
                    res.status(500).json({ error: 'No se pudo completar la transacción' });
                });
            }

            res.status(200).json({ mensaje: 'La venta ha sido pagada correctamente' });
        });
    } catch (error) {
        console.error('Error al pagar la venta:', error.stack);
        connection.rollback(() => {
            res.status(500).json({ error: 'No se pudo pagar la venta' });
        });
    } finally {
        closeDbConnection(connection);
    }
});




app.get('/', (req, res) => {
    res.send('Hello, World!');
});

const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Servidor corriendo en el puerto ${port}`);
});
