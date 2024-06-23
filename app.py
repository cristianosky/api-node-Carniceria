from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

# Importar funciones de base de datos
from db import get_db_connection, close_db_connection

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'tu_clave_secreta'  # Cambia esto por una clave segura en producción
jwt = JWTManager(app)

# Ruta para obtener todos los usuarios (requiere autenticación)
@app.route('/usuarios', methods=['GET'])
@jwt_required()
def get_usuarios():
    connection = get_db_connection()
    if connection is None:
        return jsonify({"error": "No se pudo conectar a la base de datos"}), 500

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT id, nombre, usuario, estado FROM usuarios")
    rows = cursor.fetchall()
    cursor.close()
    close_db_connection(connection)

    return jsonify(rows)

# Ruta para registrar un nuevo usuario
@app.route('/registro', methods=['POST'])
def registrar_usuario():
    data = request.get_json()
    
    nombre = data.get('nombre')
    usuario = data.get('usuario')
    contrasena = data.get('contrasena')
    estado = data.get('estado', 1)  # Estado predeterminado es 1

    if not nombre or not usuario or not contrasena:
        return jsonify({"error": "Faltan campos obligatorios"}), 400

    contrasena_hasheada = generate_password_hash(contrasena)

    connection = get_db_connection()
    if connection is None:
        return jsonify({"error": "No se pudo conectar a la base de datos"}), 500

    cursor = connection.cursor()
    try:
        cursor.execute("""
            INSERT INTO usuarios (nombre, usuario, contrasena, estado)
            VALUES (%s, %s, %s, %s)
        """, (nombre, usuario, contrasena_hasheada, estado))
        connection.commit()
    except Exception as e:
        print(f"Error al registrar usuario: {e}")
        return jsonify({"error": "No se pudo registrar el usuario"}), 500
    finally:
        cursor.close()
        close_db_connection(connection)

    return jsonify({"mensaje": "Usuario registrado correctamente"}), 201

# Ruta para realizar el inicio de sesión y obtener token JWT
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    usuario = data.get('usuario')
    contrasena = data.get('contrasena')

    if not usuario or not contrasena:
        return jsonify({"error": "Falta usuario o contraseña"}), 400

    connection = get_db_connection()
    if connection is None:
        return jsonify({"error": "No se pudo conectar a la base de datos"}), 500

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM usuarios WHERE usuario = %s", (usuario,))
    usuario_db = cursor.fetchone()
    cursor.close()
    close_db_connection(connection)

    if not usuario_db or not check_password_hash(usuario_db['contrasena'], contrasena):
        return jsonify({"error": "Usuario o contraseña inválidos"}), 401

    # Generar token JWT
    access_token = create_access_token(identity=usuario_db['usuario'])

    usuario_db.pop('contrasena', None)
    
    return jsonify({"mensaje": "Inicio de sesión exitoso", "access_token": access_token, "usuario": usuario_db}), 200

# Ruta protegida que requiere token JWT para acceder
@app.route('/recurso_protegido', methods=['GET'])
@jwt_required()
def recurso_protegido():
    current_user = get_jwt_identity()
    return jsonify(mensaje="Acceso permitido", usuario=current_user), 200

if __name__ == '__main__':
    app.run(debug=True)
