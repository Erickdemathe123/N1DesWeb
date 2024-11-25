from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'database.db'


def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


@app.route('/initdb')
def initialize_database():
    init_db()
    return 'Banco de dados inicializado'


# Decorador para autenticação
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Você precisa estar logado para acessar esta página.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Decorador para autorização baseada em função
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Verificação da role do usuário
            user_role = session.get('user_role')
            print("Role do usuário:", user_role)  # Adicionado para depuração
            if user_role != role:
                flash('Você não tem permissão para acessar esta página.')
                return redirect(url_for('home'))  # Redireciona para a página inicial se não for admin
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/usuarios', methods=['POST'])
def create_user():
    data = request.json
    login = data.get('login')
    senha = generate_password_hash(data.get('senha'))  # Encriptação da senha
    nome = data.get('nome')

    if '@' not in login:
        return jsonify({'message': 'O login deve ser um e-mail válido'}), 400

    db = get_db()
    try:
        db.execute(
            'INSERT INTO usuarios (login, senha, nome, data_criacao, status, role) VALUES (?, ?, ?, ?, ?, ?)',
            (login, senha, nome, datetime.now(), 'ativo', 'user')  # Função padrão é 'user'
        )
        db.commit()
        return jsonify({'message': 'Usuário criado com sucesso!'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Usuário com este login já existe!'}), 400
    finally:
        db.close()


@app.route('/usuarios', methods=['GET'])
@login_required
@role_required('admin')  # Verifica se o usuário tem a role 'admin'
def get_users():
    db = get_db()
    users = db.execute('SELECT * FROM usuarios').fetchall()
    return render_template('usuarios.html', users=users)


@app.route('/usuarios/<int:id>', methods=['PUT'])
@login_required
@role_required('admin')
def update_user(id):
    data = request.json
    nome = data.get('nome')
    status = data.get('status')

    db = get_db()
    db.execute(
        'UPDATE usuarios SET nome = ?, status = ?, data_ultima_atualizacao = ? WHERE id = ?',
        (nome, status, datetime.now(), id)
    )
    db.commit()
    return jsonify({'message': 'Usuário atualizado com sucesso!'}), 200


@app.route('/usuarios/<int:id>/bloquear', methods=['POST'])
@login_required
@role_required('admin')
def block_user(id):
    db = get_db()
    db.execute('UPDATE usuarios SET status = ? WHERE id = ?', ('bloqueado', id))
    db.commit()

    user = db.execute('SELECT * FROM usuarios WHERE id = ?', (id,)).fetchone()

    return render_template('bloquear_usuario.html', user=user)


@app.route('/usuarios/<int:id>/ativar', methods=['POST'])
@login_required
@role_required('admin')
def activate_user(id):
    db = get_db()
    db.execute('UPDATE usuarios SET status = ? WHERE id = ?', ('ativo', id))
    db.commit()

    user = db.execute('SELECT * FROM usuarios WHERE id = ?', (id,)).fetchone()

    return render_template('ativar_usuario.html', user=user)


@app.route('/usuarios/<int:id>/editar', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(id):
    db = get_db()
    user = db.execute('SELECT * FROM usuarios WHERE id = ?', (id,)).fetchone()

    if request.method == 'POST':
        nome = request.form['nome']
        status = request.form['status']
        db.execute(
            'UPDATE usuarios SET nome = ?, status = ?, data_ultima_atualizacao = ? WHERE id = ?',
            (nome, status, datetime.now(), id)
        )
        db.commit()
        flash('Usuário atualizado com sucesso!')
        return redirect(url_for('get_users'))

    return render_template('editar_usuario.html', user=user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form['login']
        senha = request.form['senha']

        db = get_db()
        user = db.execute('SELECT * FROM usuarios WHERE login = ?', (login,)).fetchone()

        if user and check_password_hash(user['senha'], senha):
            if user['status'] == 'bloqueado':
                flash('Seu usuário está bloqueado!')
                return redirect(url_for('login'))

            db.execute(
                'UPDATE usuarios SET data_ultima_atualizacao = ? WHERE id = ?',
                (datetime.now(), user['id'])
            )
            db.commit()

            # Armazenar informações do usuário na sessão
            session['user_id'] = user['id']
            session['user_role'] = user['role']  # Corrigido para garantir a role seja atribuída corretamente

            flash('Login bem-sucedido!')
            return redirect(url_for('home'))
        else:
            flash('Login ou senha incorretos!')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Logout realizado com sucesso.')
    return redirect(url_for('login'))


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        login = request.form['login']
        senha = request.form['senha']
        nome = request.form['nome']
        role = request.form.get('role', 'user')  # Pega a role do formulário, se não houver, define como 'user'

        if '@' not in login:
            flash('O login deve ser um e-mail válido')
            return redirect(url_for('register'))

        senha_encriptada = generate_password_hash(senha)

        db = get_db()
        try:
            db.execute(
                'INSERT INTO usuarios (login, senha, nome, data_criacao, status, role) VALUES (?, ?, ?, ?, ?, ?)',
                (login, senha_encriptada, nome, datetime.now(), 'ativo', role)  # Aqui a role é definida a partir do formulário
            )
            db.commit()
            flash('Usuário registrado com sucesso!')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Este e-mail já está registrado!')
            return redirect(url_for('register'))
        finally:
            db.close()
    return render_template('register.html')



@app.route('/usuarios/<int:id>/promover', methods=['POST'])
@login_required
@role_required('admin')
def promote_user(id):
    db = get_db()
    # Alterar o status do usuário para 'admin', ou outra lógica de promoção
    db.execute('UPDATE usuarios SET role = ? WHERE id = ?', ('admin', id))
    db.commit()

    flash('Usuário promovido com sucesso!')
    return redirect(url_for('get_users'))


if __name__ == '__main__':
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.run(debug=True)
