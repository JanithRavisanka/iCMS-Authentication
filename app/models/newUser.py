from pydantic import BaseModel


class NewUser(BaseModel):
    username: str
    password: str
    email: str
    phone_number: str
    roles: list[str]
