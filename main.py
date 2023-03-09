from flask import Flask, render_template, request, redirect, session
import sqlite3
from passlib.hash import pbkdf2_sha256
import os


app = Flask(__name__)
app.secret_key = 'dqsddqkj172KJndzida87'

# Définition de la route pour la page d'accueil
@app.route('/')
def home():
    return render_template('home.html')

# Définition de la route pour la page du formulaire
@app.route('/form', methods=['GET', 'POST'])
def form():
    if 'name' in session and 'email' in session:
        # Récupération des données de l'utilisateur dans la session
        name = session['name']
        email = session['email']
    else:
        # Réinitialisation des données du formulaire
        name = ''
        email = ''

    if request.method == 'POST':
        # Récupération des données du formulaire
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # Stockage des données de l'utilisateur dans la session
        session['name'] = name
        session['email'] = email

        # Connexion à la base de données
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        # Exécution de la requête SQL pour insérer les données dans la table
        c.execute('INSERT INTO messages (name, email, message) VALUES (?, ?, ?)', (name, email, message))

        # Enregistrement des modifications et fermeture de la connexion
        conn.commit()
        conn.close()

        # Redirection vers la page de confirmation
        return render_template('confirmation.html', name=name)

    else:
        # Affichage du formulaire
        return render_template('form.html', name=name, email=email)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Récupération des données du formulaire de connexion
        username = request.form['username']
        password = request.form['password']

        # Connexion à la base de données
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        # Exécution de la requête SQL pour récupérer le mot de passe haché correspondant à l'utilisateur
        c.execute('SELECT password FROM users WHERE username = ?', (username,))
        result = c.fetchone()

        # Vérification du mot de passe
        if result and pbkdf2_sha256.verify(password, result[0]):
            session['username'] = username
            return redirect('/')
        else:
            return render_template('login.html', error='Identifiants incorrects')

    else:
        return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Récupération des données du formulaire
        username = request.form['username']
        password = request.form['password']

        # Connexion à la base de données
        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        # Vérification si l'utilisateur existe déjà dans la base de données
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        result = c.fetchone()
        if result:
            return render_template('register.html', error='Cet identifiant est déjà utilisé.')

        # Hashage du mot de passe
        hashed_password = pbkdf2_sha256.hash(password)

        # Exécution de la requête SQL pour insérer les données dans la table
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))

        # Enregistrement des modifications et fermeture de la connexion
        conn.commit()
        conn.close()

        # Redirection vers la page de connexion
        return redirect('/login')

    else:
        # Affichage du formulaire
        return render_template('register.html')
@app.route('/logout')
def logout():
    # Suppression des données de l'utilisateur de la session
    session.pop('username', None)

    # Redirection vers la page d'accueil
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)