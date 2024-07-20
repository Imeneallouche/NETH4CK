from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(
        __name__,
        template_folder='../templates',  # Explicitly set the templates folder
        static_folder='../static'  # Explicitly set the static folder
    )
    app.config.from_object('config.Config')

    db.init_app(app)
    migrate.init_app(app, db)

    with app.app_context():
        from . import views, models
        db.create_all()

    return app

