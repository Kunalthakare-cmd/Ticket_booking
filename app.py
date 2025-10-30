from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from datetime import datetime
from collections import Counter
import hashlib

app = Flask(__name__)
CORS(app)

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['ticket_booking_db']
bookings_collection = db['bookings']

# Create index on fingerprint for faster queries
bookings_collection.create_index('fingerprint')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/book', methods=['POST'])
def book_ticket():
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['name', 'source', 'destination', 'fingerprint']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Create booking record
        booking = {
            'name': data['name'],
            'source': data['source'],
            'destination': data['destination'],
            'fingerprint': data['fingerprint'],
            'fingerprint_hash': hashlib.md5(data['fingerprint'].encode()).hexdigest()[:8],
            'timestamp': datetime.utcnow(),
            'ip_address': request.remote_addr
        }
        
        # Insert into database
        result = bookings_collection.insert_one(booking)
        
        # Check if suspicious (more than 3 bookings)
        booking_count = bookings_collection.count_documents({
            'fingerprint': data['fingerprint']
        })
        
        is_suspicious = booking_count > 3
        
        return jsonify({
            'success': True,
            'booking_id': str(result.inserted_id),
            'booking_count': booking_count,
            'is_suspicious': is_suspicious,
            'message': 'Ticket booked successfully!'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    try:
        # Get all bookings
        all_bookings = list(bookings_collection.find())
        
        # Count bookings per fingerprint
        fingerprint_counts = Counter(booking['fingerprint'] for booking in all_bookings)
        
        # Identify suspicious users (>3 bookings)
        suspicious_fingerprints = {fp: count for fp, count in fingerprint_counts.items() if count > 3}
        
        # Get unique fingerprints
        unique_fingerprints = len(fingerprint_counts)
        
        # Total bookings
        total_bookings = len(all_bookings)
        
        # Suspicious bookings count
        suspicious_bookings = sum(suspicious_fingerprints.values())
        
        # Prepare detailed data
        fingerprint_details = []
        for fp, count in fingerprint_counts.items():
            fp_bookings = [b for b in all_bookings if b['fingerprint'] == fp]
            
            # Get unique names and routes
            names = list(set(b['name'] for b in fp_bookings))
            routes = list(set(f"{b['source']} → {b['destination']}" for b in fp_bookings))
            
            fingerprint_details.append({
                'fingerprint_id': hashlib.md5(fp.encode()).hexdigest()[:8],
                'full_fingerprint': fp,
                'booking_count': count,
                'is_suspicious': count > 3,
                'names_used': names,
                'routes': routes,
                'last_booking': max(b['timestamp'] for b in fp_bookings).isoformat(),
                'bookings': [{
                    'name': b['name'],
                    'route': f"{b['source']} → {b['destination']}",
                    'timestamp': b['timestamp'].isoformat(),
                    'ip': b.get('ip_address', 'N/A')
                } for b in sorted(fp_bookings, key=lambda x: x['timestamp'], reverse=True)]
            })
        
        # Sort by booking count (suspicious first)
        fingerprint_details.sort(key=lambda x: x['booking_count'], reverse=True)
        
        # Booking timeline (last 24 hours by hour)
        timeline_data = {}
        for booking in all_bookings:
            hour = booking['timestamp'].strftime('%Y-%m-%d %H:00')
            timeline_data[hour] = timeline_data.get(hour, 0) + 1
        
        timeline = sorted([{'time': k, 'count': v} for k, v in timeline_data.items()], 
                         key=lambda x: x['time'])
        
        return jsonify({
            'success': True,
            'summary': {
                'total_bookings': total_bookings,
                'unique_fingerprints': unique_fingerprints,
                'suspicious_users': len(suspicious_fingerprints),
                'suspicious_bookings': suspicious_bookings,
                'fraud_rate': round(suspicious_bookings / total_bookings * 100, 2) if total_bookings > 0 else 0
            },
            'fingerprint_details': fingerprint_details,
            'timeline': timeline[-24:]  # Last 24 data points
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/clear', methods=['POST'])
def clear_data():
    try:
        bookings_collection.delete_many({})
        return jsonify({'success': True, 'message': 'All data cleared successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)