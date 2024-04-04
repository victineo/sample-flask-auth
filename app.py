from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:\\Users\\GAMER\\Desktop\\codigos\\Rocketseat\\Python\\Módulo 4\\sample-flask-auth\\instance\\database.db'

login_manager = LoginManager()
db.init_app(app) # Iniciando a instância do SQLAlchemy 'db' com a aplicação Flask 'app'
login_manager.init_app(app)
# View login
login_manager.login_view = 'login'
# Session <= conexão ativa

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, user_id) # Buscando no BD o user que possui esse ID e retornando ele

@app.route('/login', methods=['POST'])
def login():
    data = request.json # Recebendo dados enviados no JSON
    username = data.get('username') # Extraindo 'username' do JSON
    password = data.get('password') # Extraindo 'password' do JSON

    if username and password: # Conferindo se há 'username' e 'password'
        # Login
        user = User.query.filter_by(username=username).first() # Buscando no BD o primeiro user com esse nome

        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)): # Verificando de há um user com tal nome e se a senha coincide com a cadastrada no BD
            login_user(user) # Autenticando user
            return jsonify({'message': 'Autenticação realizada com sucesso.'})
    
    return jsonify({'message': 'Credenciais inválidas.'}), 400 # Bad Request

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout realizado com sucesso.'})

@app.route('/user', methods=['POST'])
def create_user():
    data = request.json # Recebendo dados enviados no JSON
    username = data.get('username') # Extraindo 'username' do JSON
    password = data.get('password') # Extraindo 'password' do JSON

    if username and password: # Verificando se os dados 'username' e 'password' foram enviados
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())  # Criptografando a senha
        user = User(username=username, password=hashed_password, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'Usuário cadastrado com sucesso.'})

    return jsonify({'message': 'Dados inválidos.'}), 400 # Bad Request

@app.route('/user/<int:id_user>', methods=['GET'])
@login_required
def read_user(id_user):
    user = User.query.get(id_user) # Buscando no BD o usuário com tal ID

    if user:
        return {'username': user.username}
    
    return jsonify({'message': 'Usuário não encontrado.'}), 404 # Not Found

@app.route('/user/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
    data = request.json # Recebendo dados enviados no JSON
    user = User.query.get(id_user) # Buscando no BD o usuário com tal ID

    if id_user != current_user.id and current_user.role == 'user': # Se o ID solicitado for diferente do que está em uso E a role for de 'user', a operação é negada
        return jsonify({'message': 'Operação não permitida. Você não pode alterar informações de outros usuários.'}), 403 # Forbidden
    if user and data.get('password'): # Se houver esse usuário e uma senha enviada no JSON
        user.password = data.get('password') # A senha será definida como o que veio no JSON
        db.session.commit()
        return jsonify({'message': f'Usuário {id_user} atualizado com sucesso.'})
    
    return jsonify({'message': 'Usuário não encontrado.'}), 404 # Not Found

@app.route('/user/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
    user = db.session.get(User, id_user) # Buscando no BD o usuário com tal ID

    if current_user.role != 'admin': # Se a role não for 'admin', a operação é negada
        return jsonify({'message': 'Operação não permitida. Você não pode deletar outros usuários.'}), 403 # Forbidden
    if id_user == current_user.id: # Se o ID solicitado for igual ao que está em uso atualmente
        return jsonify({'message': 'Operação não permitida. Você não pode deletar a si mesmo.'}), 403 # Forbidden

    if user: # Se houver esse usuário
        db.session.delete(user) # Delete
        db.session.commit()
        return jsonify({'message': f'Usuário {id_user} deletado com sucesso.'})
    
    return jsonify({'message': 'Usuário não encontrado.'}), 404 # Not Found

if __name__ == '__main__':
    app.run(debug=True)