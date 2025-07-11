from flask_socketio import SocketIO

socketio = None

def init_socketio(sio):
    global socketio
    socketio = sio

def broadcast_arp_alert(alert):
    # alert: (timestamp, attack_type, description, source_ip)
    if socketio:
        socketio.emit('new_arp_alert', {
            'timestamp': alert[0],
            'attack_type': alert[1],
            'description': alert[2],
            'source_ip': alert[3]
        }) 