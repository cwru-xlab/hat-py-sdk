from flask import current_app


def add_routes():
    @current_app.route('/hello')
    def hello():
        return 'Hello, World!'
