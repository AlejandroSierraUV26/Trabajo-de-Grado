from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
from dotenv import load_dotenv

# Cargamos variables de entorno (.env)
load_dotenv()

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    # Configuración de la base de datos SQLite
    # Se guardará en la carpeta 'instance' del proyecto
    basedir = os.path.abspath(os.path.dirname(__file__))
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, '..', 'instance', 'security_monitor.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'dev-key-para-tesis' # Cambiar en producción

    db.init_app(app)

    with app.app_context():
        # Importamos las rutas y modelos dentro del contexto
        from . import routes, models
        
        # Crea las tablas en la base de datos si no existen
        db.create_all()

    return app