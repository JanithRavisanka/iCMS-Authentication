from pydantic import BaseModel
from typing import Optional


class User(BaseModel):
    user_name: str


class groupPermissions(BaseModel):
    name: str
    value: bool


class userGroup(BaseModel):
    group_name: str
    permissions: list[groupPermissions]
    users: Optional[list[User]] = None
