from pydantic import BaseModel


class SubscribeUser(BaseModel):
    username: str
    type: str
