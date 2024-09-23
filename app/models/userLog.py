from typing import List

from pydantic import BaseModel



class LogEntry(BaseModel):
    action: str
    is_success: bool
    time: str

class UserLogs(BaseModel):
    username: str
    creation: dict
    events: List[LogEntry]
