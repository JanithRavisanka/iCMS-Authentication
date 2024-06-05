from pydantic import BaseModel


class DeleteUser(BaseModel):
    username: str
