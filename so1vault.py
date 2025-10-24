import argparse, secrets, os, stat, re, sqlite3
from flask import Flask, redirect, url_for, render_template, request, session
from argon2 import PasswordHasher
from datetime import timedelta, datetime
from cryptography.fernet import Fernet
pass_hash = PasswordHasher(hash_len = 128, salt_len = 16)



# if script is run for the 1st time it creates a database + generates a key for hashing
if not os.path.exists('passwords.db'):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE passwords (id INTEGER PRIMARY KEY AUTOINCREMENT, email BLOB, password BLOB, url BLOB, last_modified TEXT, first_created TEXT)')
        conn.commit()
    os.chmod('passwords.db', stat.S_IRWXU)
    key = Fernet.generate_key()
    with open("secret.key", 'wb') as f:
        f.write(key)
        os.chmod('secret.key', stat.S_IRUSR | stat.S_IWUSR)


def get_db_connection():
    conn = sqlite3.connect('passwords.db', check_same_thread=False)
    return conn

# loads the fernet keys for encrypt/decrypting
def load_key():
    with open("secret.key", 'rb') as f:
        return f.read()

# encrypts data
def encrypt_data(data):
    data = data.encode()
    key = load_key()
    fernet = Fernet(key)
    return fernet.encrypt(data)

# makes sure a user is authorized
def authorization(password=None):
    try:
        if os.path.exists("master_key.txt"):
            with open('master_key.txt', 'r') as f:
                return f.read()
        else:
            with open('master_key.txt', 'w') as f:
                f.write(pass_hash.hash(password))
                os.chmod('master_key.txt', stat.S_IRWXU)
                return pass_hash.hash(password)
    except Exception as e:
        return f'<h1>{e}</h1>'

# main function
def main():

    # sets up argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, default=8080)
    parser.add_argument('--session-time', type=int, default=10)
    parser.add_argument('--debug', action='store_true', default=False)
    args = parser.parse_args()

    # sets up flask
    web_site = Flask(__name__)
    web_site.secret_key = secrets.token_hex(256)
    web_site.permanent_session_lifetime = timedelta(minutes = args.session_time)

    @web_site.route('/', methods=['GET', 'POST'])
    def home():
        session.permanent = True
        if os.path.exists('master_key.txt'):
            return redirect(url_for('login'))

        elif request.method == 'POST':
            try:
                site_password = request.form["master_password"]
                authorization(site_password)
                session['authorized'] = True
                return redirect(url_for('dashboard'))
            except Exception as e:
                return f"<h1>{e}</h1>"
        return render_template("first.html")


    @web_site.route('/login/', methods=['GET', 'POST'])
    def login():
        try:
            if 'authorized' in session:
                return redirect(url_for('dashboard'))

            if os.path.exists('master_key.txt'):
                if request.method == 'GET':
                    return render_template('login.html')
                else:
                    site_password = request.form["master_password"]
                    master_password = authorization()
                    if pass_hash.verify(master_password, site_password):
                        session['authorized'] = True
                        return redirect(url_for('dashboard'))
            return redirect(url_for('home'))
        except Exception as e:
            return f'<h1>{e}</h1>'

    @web_site.route('/dashboard/')
    def dashboard():
        if 'authorized' in session:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                key = load_key()
                fernet = Fernet(key)
                cursor.execute('SELECT * FROM passwords')
                data = cursor.fetchall()
                return render_template('dashboard.html', data=data, fernet=fernet)
        return redirect(url_for('home'))


    @web_site.route('/dashboard/add/', methods=['GET', 'POST'])
    def add():
        if 'authorized' in session:
            if request.method == 'GET':
                return render_template('add.html')
            else:
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    email = request.form['email']
                    password = request.form['password']
                    url = request.form['url']
                    last_modified = datetime.now().strftime('%H:%M %d-%m-%y')
                    first_created = datetime.now().strftime('%H:%M %d-%m-%y')
                    cursor.execute('INSERT INTO passwords (email, password, url, last_modified, first_created) VALUES (?, ?, ?, ?, ?)',(encrypt_data(email), encrypt_data(password), encrypt_data(url), str(last_modified), str(first_created)))
                    conn.commit()
                    return redirect(url_for('dashboard'))
        return redirect(url_for('home'))

    @web_site.route('/dashboard/delete/<int:id_num>/', methods=['POST'])
    def delete(id_num):
        if 'authorized' in session:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM passwords WHERE id=?', (id_num,))
                return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('home'))

    @web_site.route('/dashboard/edit/<int:id_num>', methods=['GET', 'POST'])
    def edit(id_num):
        if 'authorized' in session:
            key = load_key()
            fernet = Fernet(key)
            if request.method == 'GET':

                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT * FROM passwords WHERE id=?', (id_num,))
                    row = cursor.fetchall()
                    print(row)
                    data = {
                        'email':fernet.decrypt(row[0][1]).decode(),
                        'password':fernet.decrypt(row[0][2]).decode(),
                        'url':fernet.decrypt(row[0][3]).decode()
                        }
                    return render_template('edit.html', data=data)
            else:
                with get_db_connection() as conn:
                    cursor = conn.cursor()
                    email = request.form['email'].encode()
                    password = request.form['password'].encode()
                    url = request.form['url'].encode()


                    if email:
                        cursor.execute('UPDATE passwords SET email=? WHERE id=?', (fernet.encrypt(email), id_num,))
                    if password:
                        cursor.execute('UPDATE passwords SET password=? WHERE id=?', (fernet.encrypt(password), id_num,))
                    if url:
                        cursor.execute('UPDATE passwords SET url=? WHERE id=?', (fernet.encrypt(url), id_num,))

                    cursor.execute('UPDATE passwords SET last_modified=? WHERE id=?', (str(datetime.now().strftime('%H:%M %d-%m-%y')), id_num,))
                    conn.commit()
                    return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('home'))



    @web_site.errorhandler(404)
    def invalid_url(e):
        return redirect(url_for("home"))

    web_site.run(host='127.0.0.1', port=args.port, debug=args.debug, ssl_context=('cert.pem', 'key.pem'))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f'exiting..')
    except Exception as e:
        print(f'error: {e}')


