import uuid
from core.database.queries import insert_session, close_session, increment_command_count


class SessionManager:

    def create_session(self, source_ip):
        session_id = str(uuid.uuid4())
        insert_session(session_id, source_ip)
        return session_id

    def end_session(self, session_id, status="closed"):
        close_session(session_id, status)

    def register_command(self, session_id):
        increment_command_count(session_id)