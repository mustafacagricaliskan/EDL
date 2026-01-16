import logging

from flask import Blueprint, jsonify, render_template, request

from .auth import login_required

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

@bp_tools.route('/api/lookup_internal', methods=['POST'])
@login_required
def lookup_internal():
    try:
        data = request.get_json()
        indicator = data.get('indicator')

        if not indicator:
            return jsonify({'success': False, 'error': 'No indicator provided'}), 400

        from ..db_manager import get_sources_for_indicator
        sources = get_sources_for_indicator(indicator)

        return jsonify({'success': True, 'sources': sources})

    except Exception as e:
        logger.error(f"Error in lookup_internal: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
