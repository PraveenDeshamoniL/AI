
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from auth import auth_bp
from models import db, User, ScanLog
from detector import predict_url, check_malware
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

app = Flask(__name__)
app.secret_key = 'super-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'docx'}
BLOCKED_EXTENSIONS = {'.exe', '.py', '.sh', '.bat', '.jar', '.php'}

def allowed_file(filename):
    ext = os.path.splitext(filename)[1].lower()
    return ext in ('.' + e for e in ALLOWED_EXTENSIONS) and ext not in BLOCKED_EXTENSIONS

db.init_app(app)
Talisman(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

app.register_blueprint(auth_bp)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    result = ''
    if request.method == 'POST':
        url = request.form['url']
        file = request.files.get('file')
        result = predict_url(url)

        malware = "No File"
        if file and allowed_file(file.filename):
            path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(path)
            malware = "Yes" if check_malware(path) else "No"
            result += f" | Malware: {malware}"
        elif file and not allowed_file(file.filename):
            flash("❌ File type not allowed!", "danger")
            return redirect(url_for('index'))

        log = ScanLog(user_id=current_user.id, url=url, malware_result=malware)
        db.session.add(log)
        db.session.commit()

    return render_template('index.html', result=result, user=current_user)

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        abort(403)
    logs = ScanLog.query.order_by(ScanLog.timestamp.desc()).all()
    return render_template('dashboard.html', logs=logs)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
