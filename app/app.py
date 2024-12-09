from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Instancia de Flask y configuración
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/forum?client_flag=2'
app.config['SQLALCHEMY_ECHO'] = False
app.secret_key = 'secret_key'

# Instanciando db
db = SQLAlchemy(app)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:  # Si no hay un usuario autenticado en la sesión
            flash('Debes iniciar sesión para acceder a esta página.', 'warning')
            return redirect(url_for('login'))  # Redirigir a la página de inicio de sesión
        return f(*args, **kwargs)  # Continuar con la ejecución de la función original
    return decorated_function

# Modelos
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    posts = db.relationship('Post', backref='user', lazy=True)  # Relación con Post

class Subforum(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(250))
    posts = db.relationship('Post', backref='subforum', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subforum_id = db.Column(db.Integer, db.ForeignKey('subforum.id'), nullable=False)
    replies = db.relationship('Reply', backref='post_reply', lazy=True)  # Cambiar nombre de backref

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Bookmark(db.Model):
    __tablename__ = 'bookmark'
    
    id = db.Column(db.Integer, primary_key=True)
    bookmark_name = db.Column(db.String(255), nullable=False)
    page_number = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Asegúrate de tener este campo

    user = db.relationship('User', backref=db.backref('bookmarks', lazy=True))

    def __init__(self, bookmark_name, page_number, user_id):  # Asegúrate de que este constructor acepte user_id
        self.bookmark_name = bookmark_name
        self.page_number = page_number
        self.user_id = user_id

# Crear tablas y subforos predeterminados antes de procesar solicitudes
with app.app_context():
    db.create_all()
    if not Subforum.query.first():
        db.session.add_all([
            Subforum(name='Personaje favorito', description='¡Comparte tu personaje favorito!'),
            Subforum(name='Parte favorita', description='Comparte tu parte favorita y conversa'),
            Subforum(name='Opinion de AURA', description='Discusion y opinion sobre la obra'),
            Subforum(name='Otras obras???', description='Muestra otras obras de Carlos Fuentes')
        ])
        db.session.commit()

@app.route('/')
def home():
    user_info = {}  # Diccionario para almacenar la información del usuario
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        user_info = {'username': user.username,
                     'user_id': user.id}
    
    return render_template('home.html', user_info=user_info)
# Rutas
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        
        if password != password_confirm:
            flash('Las contraseñas no coinciden.', 'danger')
            return render_template('register.html')

        hashed_password = generate_password_hash(password)
        
        user = User(username=username, password=hashed_password)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Usuario registrado con éxito', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al registrar el usuario: {e}', 'danger')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Inicio de sesión exitoso', 'success')
            return redirect(url_for('home'))
        else:
            flash('Credenciales inválidas. Intenta nuevamente.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def post(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        content = request.form['content']
        new_reply = Reply(content=content, post_id=post.id, user_id=session['user_id'])
        db.session.add(new_reply)
        db.session.commit()
        return redirect(url_for('post', post_id=post.id))

    return render_template('post.html', post=post)

@app.route('/subforum/<int:subforum_id>/post', methods=['GET', 'POST'])
def create_post(subforum_id):
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        
        # Crear la nueva publicación
        new_post = Post(title=title, content=content, subforum_id=subforum_id, user_id=session['user_id'])
        db.session.add(new_post)
        db.session.commit()
        
        return redirect(url_for('forum', subforum_id=subforum_id))
    
    return render_template('post.html', subforum_id=subforum_id)

@app.route('/forum/<int:subforum_id>')
def forum(subforum_id):
    subforum = Subforum.query.get_or_404(subforum_id)
    posts = Post.query.filter_by(subforum_id=subforum_id).all()
    user_info ={}
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        user_info = {'username': user.username,
                    'user_id': user.id}
    return render_template('forum.html', subforum=subforum, posts=posts, user_info =user_info)



@app.route('/reading')
def reading():
    if 'user_id' not in session:
        flash('Por favor, inicia sesión para ver los marcadores.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    bookmarks = Bookmark.query.filter_by(user_id=user_id).all()
    user_info ={}
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        user_info = {'username': user.username,
                     'user_id': user.id}
    return render_template('reading.html', bookmarks=bookmarks, user_info=user_info)

@app.route('/bookmarks')
def bookmarks():
    user_id = session.get('user_id')
    if user_id:
        bookmarks = Bookmark.query.filter_by(user_id=user_id).all()  # Obtener los marcadores del usuario
        print(f'Marcadores del usuario {user_id}: {bookmarks}')  # Verificar qué marcadores se están obteniendo
        user_info ={}
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.get(user_id)
        user_info = {'username': user.username,
                     'user_id': user.id}
        
        return render_template('bookmarks.html', bookmarks=bookmarks, user_info=user_info)
    
    else:
        flash('Debes iniciar sesión para ver tus marcadores.')
        return redirect(url_for('login'))

    
@app.route('/add_bookmark', methods=['POST'])
def add_bookmark():
    bookmark_name = request.form['bookmark_name']
    page_number = request.form['page_number']
    user_id = session['user_id']  # Supongo que el ID del usuario está en la sesión

    new_bookmark = Bookmark(bookmark_name=bookmark_name, page_number=page_number, user_id=user_id)

    db.session.add(new_bookmark)
    db.session.commit()

    return redirect(url_for('reading'))

@app.route('/reading/<int:page_number>')
def reading_page(page_number):
    print(f"Página solicitada: {page_number}")  # Depuración
    # Aquí cargarías la página del PDF
    return render_template('reading.html', current_page_number=page_number)

@app.context_processor
def inject_subforums():
    subforums = Subforum.query.all()
    return {'subforums': subforums}

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Esto crea las tablas si no existen
    app.run(debug=True)
