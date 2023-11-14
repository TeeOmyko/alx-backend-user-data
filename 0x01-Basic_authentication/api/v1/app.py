#!/usr/bin/env python3
""" Module of Index views
"""
from flask import jsonify, abort
from api.v1.views import app_views

@app_views.route('/status', methods=['GET'], strict_slashes=False)
def status() -> str:
    """ GET /api/v1/status
    Return:
      - the status of the API
    """
    return jsonify({"status": "OK"})

@app_views.route('/stats/', strict_slashes=False)
def stats() -> str:
    """ GET /api/v1/stats
    Return:
      - the number of each objects
    """
    from models.user import User
    stats = {}
    stats['users'] = User.count()
    return jsonify(stats)

# New endpoint for testing Forbidden error
@app_views.route('/forbidden', methods=['GET'], strict_slashes=False)
def forbidden_endpoint() -> str:
    """ GET /api/v1/forbidden
    Raise a 403 Forbidden error
    """
    abort(403)

# Error handler for 403 Forbidden
@ app_views.errorhandler(403)
def forbidden_error(error):
    """ Handles 403 Forbidden error """
    response = jsonify({"error": "Forbidden"})
    response.status_code = 403
    return response
