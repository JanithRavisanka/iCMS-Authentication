from fastapi import Body
from pydantic import BaseModel


class ChangePassword(BaseModel):
    PreviousPassword: str = Body(..., embed=True)
    ProposedPassword: str = Body(..., embed=True)
    AccessToken: str = Body(..., embed=True)
