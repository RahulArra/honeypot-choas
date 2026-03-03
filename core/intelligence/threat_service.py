from core.intelligence.classifier import classify_command
from core.database.queries import insert_threat
from core.adaptive.escalation import update_adaptive_score

def handle_threat_detection(session_id, command_id, raw_input):
    """
    Orchestrator: Bridges the gap between raw text analysis and 
    database persistence/adaptive logic.
    """
    try:
        # 1. Ask the classifier if this text is dangerous
        threat_data = classify_command(raw_input)
        
        if threat_data:
            # 2. It is dangerous! Log it to the 'threats' table
            insert_threat(
                session_id=session_id,
                command_id=command_id,
                threat_type=threat_data['type'],
                severity=threat_data['severity'],
                confidence=threat_data['confidence'],
                source="rule"
            )
            
            # 3. Update the persistence-based adaptive score
            new_severity, new_intensity = update_adaptive_score(session_id, threat_data['type'])
            
            return {
                "detected": True,
                "type": threat_data['type'],
                "adaptive_severity": new_severity,
                "chaos_level": new_intensity
            }
        
        # Safe default for non-malicious commands
        return {"detected": False, "chaos_level": 1}

    except Exception as e:
        print(f"DEBUG: Threat Service Error: {e}")
        return {"detected": False, "chaos_level": 1}