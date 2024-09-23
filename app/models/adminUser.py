from pydantic import BaseModel


class DeleteUser(BaseModel):
    username: str

class UpdateUser(BaseModel):
    username: str
    email: str
    phone_number: str
    roles: list[str]
