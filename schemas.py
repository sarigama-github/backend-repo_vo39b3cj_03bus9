"""
Database Schemas for Nexus Explorer

Each Pydantic model corresponds to a MongoDB collection. The collection
name is the lowercase of the class name.
"""

from pydantic import BaseModel, Field
from typing import Optional, List


class User(BaseModel):
    """
    Users collection schema
    Collection: "user"
    """
    username: str = Field(..., min_length=3, max_length=32)
    email: str = Field(...)
    password_hash: str = Field(..., description="Stored password hash with salt")
    active_tokens: Optional[List[str]] = Field(default_factory=list)


class Apikey(BaseModel):
    """
    API keys collection schema
    Collection: "apikey"
    """
    user_id: str = Field(..., description="Owner user's _id as string")
    label: Optional[str] = Field(default=None, description="Optional label or username input when creating key")
    key: str = Field(..., description="The API key string")
    usage_count: int = Field(default=0, ge=0)
