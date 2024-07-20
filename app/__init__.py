from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_socketio import SocketIO

db = SQLAlchemy()
migrate = Migrate()
socketio = SocketIO()

def create_app():
    app = Flask(
        __name__,
        template_folder='../templates',
        static_folder='../static'
    )
    app.config.from_object('config.Config')

    db.init_app(app)
    migrate.init_app(app, db)
    socketio.init_app(app)

    # Import and register the Blueprint here to avoid circular imports
    from .views import main_bp
    app.register_blueprint(main_bp)

    with app.app_context():
        db.create_all()

    return app