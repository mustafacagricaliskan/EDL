from flask import Blueprint, render_template, request, jsonify, current_app
from .auth import login_required
import requests
import logging
import whois # Added for WHOIS lookup
from ..utils import get_proxy_settings

bp_tools = Blueprint('tools', __name__, url_prefix='/tools')
logger = logging.getLogger(__name__)

@bp_tools.route('/investigate')
@login_required
def investigate():
    return render_template('investigate.html')

@bp_tools.route('/api/lookup_ip', methods=['POST'])
@login_required
def lookup_ip():
    try:
        data = request.get_json()
        ip_address = data.get('ip')
        
        if not ip_address:
            return jsonify({'success': False, 'error': 'No IP address provided'}), 400
            
        from ..services.investigation_service import InvestigationService
        result = InvestigationService.lookup_ip(ip_address)
        
        return jsonify(result)
             
    except Exception as e:
        logger.error(f"Error in lookup_ip: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
