"""
MongoDB-based OAuth token storage for Flask-Dance
"""
from typing import Dict, Optional
from flask_dance.consumer.storage.base import BaseStorage
from .. import mongo


class MongoStorage(BaseStorage):
    """
    MongoDB storage backend for Flask-Dance OAuth tokens
    """
    
    def __init__(self, collection_name: str = "oauth_tokens"):
        self.collection_name = collection_name
    
    @property
    def collection(self):
        return getattr(mongo.db, self.collection_name)
    
    def get(self, blueprint) -> Optional[Dict]:
        """Get OAuth token for the given blueprint"""
        # Use blueprint name and user (if authenticated) as key
        from flask_login import current_user
        
        query = {"blueprint": blueprint.name}
        if hasattr(current_user, 'username') and current_user.is_authenticated:
            query["user_id"] = current_user.username
        else:
            # For anonymous users, use session-based storage
            from flask import session
            if 'oauth_session_id' not in session:
                return None
            query["session_id"] = session['oauth_session_id']
        
        doc = self.collection.find_one(query)
        if doc:
            # Return token data without MongoDB-specific fields
            token = {k: v for k, v in doc.items() if k not in ('_id', 'blueprint', 'user_id', 'session_id')}
            return token
        return None
    
    def set(self, blueprint, token: Dict) -> None:
        """Store OAuth token for the given blueprint"""
        from flask_login import current_user
        from flask import session
        import secrets
        
        query = {"blueprint": blueprint.name}
        update_data = dict(token)
        update_data["blueprint"] = blueprint.name
        
        if hasattr(current_user, 'username') and current_user.is_authenticated:
            query["user_id"] = current_user.username
            update_data["user_id"] = current_user.username
        else:
            # For anonymous users, use session-based storage
            if 'oauth_session_id' not in session:
                session['oauth_session_id'] = secrets.token_hex(16)
            query["session_id"] = session['oauth_session_id']
            update_data["session_id"] = session['oauth_session_id']
        
        self.collection.update_one(
            query,
            {"$set": update_data},
            upsert=True
        )
    
    def delete(self, blueprint) -> None:
        """Delete OAuth token for the given blueprint"""
        from flask_login import current_user
        from flask import session
        
        query = {"blueprint": blueprint.name}
        if hasattr(current_user, 'username') and current_user.is_authenticated:
            query["user_id"] = current_user.username
        elif 'oauth_session_id' in session:
            query["session_id"] = session['oauth_session_id']
        else:
            return  # Nothing to delete
        
        self.collection.delete_one(query)