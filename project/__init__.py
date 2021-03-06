import os
from http import HTTPStatus

from flask import Flask, session, request, abort, redirect, url_for
from flask_login import LoginManager
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

MONGO_URL = os.getenv("MONGO_URL", default="mongodb://localhost:27017/myapp")
client = MongoClient(MONGO_URL)

# DB List
db = client.flask_db
bot_db = client.itpark

# Cluster List
coll_admin_users = db.users
collusers = bot_db.users
collreports = bot_db.reports


def create_app():
    app = Flask(__name__)

    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
    # app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.unauthorized'

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.blueprint == 'api':
            abort(HTTPStatus.UNAUTHORIZED)
        return redirect(url_for('auth.unauthorized'))

    @login_manager.user_loader
    def load_user():
        user_email = None
        if 'email' in session:
            user_email = session['email']
        x = collusers.find_one({'email': user_email})
        print("@@@@@@@@@@@@@@@@@@@@", x)
        return x

    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    from .courses import courses as courses_blueprint
    app.register_blueprint(courses_blueprint)

    return app