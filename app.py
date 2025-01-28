from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Substitua por uma chave segura
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///clients.db'  # Banco de dados SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelo do cliente
class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        address = request.form['address']
        phone = request.form['phone']

        if Client.query.filter_by(email=email).first():
            flash('E-mail já cadastrado. Faça login!', 'warning')
            return redirect(url_for('login'))

        new_client = Client(name=name, email=email, password=password, address=address, phone=phone)
        db.session.add(new_client)
        db.session.commit()

        flash('Cadastro realizado com sucesso! Faça login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        client = Client.query.filter_by(email=email).first()

        if client and check_password_hash(client.password, password):
            session['client_id'] = client.id
            session['client_name'] = client.name
            flash(f'Bem-vindo, {client.name}!', 'success')
            return redirect(url_for('dashboard'))

        flash('Credenciais inválidas. Tente novamente.', 'danger')

    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'client_id' not in session:
        flash('Por favor, faça login para acessar o dashboard.', 'warning')
        return redirect(url_for('login'))

    client = Client.query.get(session['client_id'])

    if request.method == 'POST':
        client.address = request.form['address']
        client.phone = request.form['phone']
        db.session.commit()
        flash('Informações atualizadas com sucesso!', 'success')

    return render_template('dashboard.html', client=client)

@app.route('/logout')
def logout():
    session.pop('client_id', None)
    session.pop('client_name', None)
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Cria as tabelas no banco de dados
    app.run(debug=True)

