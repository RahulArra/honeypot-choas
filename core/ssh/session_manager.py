import uuid
import time
from core.database.queries import insert_session, close_session, increment_command_count

class SessionManager:
    def __init__(self):
        # Memory-resident tracking for throttling
        self.last_command_times = {}
        self.cooldown_threshold = 0.5  # Seconds between commands to be flagged as spam

    def create_session(self, source_ip):
        session_id = str(uuid.uuid4())
        insert_session(session_id, source_ip)
        self.last_command_times[session_id] = 0
        return session_id

    def end_session(self, session_id, status="closed"):
        close_session(session_id, status)
        if session_id in self.last_command_times:
            del self.last_command_times[session_id]

    def register_command(self, session_id):
        increment_command_count(session_id)

    def get_throttle_delay(self, session_id):
        """Returns the delay in seconds if the user is spamming."""
        now = time.time()
        last_time = self.last_command_times.get(session_id, 0)
        
        # Calculate time since last command
        elapsed = now - last_time
        self.last_command_times[session_id] = now

        # If they send commands faster than 0.5s, force a 2s delay to waste bot time
        if elapsed < self.cooldown_threshold:
            return 2.0 
        return 0