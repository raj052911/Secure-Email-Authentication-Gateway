from flask import Flask
from config import Config


def create_app():

    app = Flask(__name__)

    app.config.from_object(Config)

    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

    # Import blueprints
    from app.routes.main import main_bp
    from app.routes.email import email_bp
    from app.routes.spf import spf_bp
    from app.routes.dkim import dkim_bp
    from app.routes.dmarc import dmarc_bp
    from app.routes.simulator import simulator_bp
    from app.routes.reports import reports_bp

    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(email_bp)
    app.register_blueprint(spf_bp)
    app.register_blueprint(dkim_bp)
    app.register_blueprint(dmarc_bp)
    app.register_blueprint(simulator_bp)
    app.register_blueprint(reports_bp, url_prefix="/reports")

    return app