from boto3 import client
from fastapi import APIRouter, Depends, Body, UploadFile, File, Response
from pydantic import BaseModel
from starlette.responses import JSONResponse

from app.config.config import Config
from app.utils.auth import get_current_user

user_router = APIRouter()

# Create a new boto3 client
cognito_client = client('cognito-idp')


@user_router.get("/open")
async def open_route():
    return {"message": "This is an open route"}


@user_router.get("/me")
async def read_users_me(current_user=Depends(get_current_user)):
    return current_user


@user_router.post("/uploadProfileImage")
async def upload_profile_image(file: UploadFile = File(...), user=Depends(get_current_user)):
    # upload file to s3 bucket and get the url
    key = f"{user.username}/{user.username.split('@')[0]}x.png"
    try:
        file_content = await file.read()
        s3_client = client('s3')
        s3_client.put_object(
            Bucket=Config.s3_bucket_name,
            Key=key,
            Body=file_content
        )
        # add the url to the user profile
        cognito_client.admin_update_user_attributes(
            UserPoolId=Config.cognito_pool_id,
            Username=user.username,
            UserAttributes=[
                {
                    'Name': 'custom:profile_image',
                    'Value': f"https://{Config.s3_bucket_name}.s3.ap-south-1.amazonaws.com/{key}"
                }
            ]
        )
        return {"message": "Image uploaded successfully"}
    except Exception as e:
        return {"message": str(e)}


@user_router.get("/getUserProfileData")
async def get_user_profile_data(user=Depends(get_current_user), response=Response):
    data = cognito_client.admin_get_user(
        UserPoolId=Config.cognito_pool_id,
        Username=user.username
    )['UserAttributes']

    headers = {
        "cache-control": "no-cache",
        "content-type": "application/json"
    }

    return JSONResponse(content=data, headers=headers)


class ChangePassword(BaseModel):
    current_password: str = Body(..., embed=True)
    new_password: str = Body(..., embed=True)


@user_router.post("/changePassword")
async def change_password(current_password: str = Body(...), new_password: str = Body(...),
                          user=Depends(get_current_user)):
    # check if the current password is correct
    try:
        cognito_client.admin_initiate_auth(
            UserPoolId=Config.cognito_pool_id,
            ClientId=Config.cognito_app_client_id,
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': user.username,
                'PASSWORD': current_password
            }
        )
    except Exception as e:
        return {"message": f"Current password is incorrect\n {e}"}

    cognito_client.admin_set_user_password(
        UserPoolId=Config.cognito_pool_id,
        Username=user.username,
        Password=new_password,
        Permanent=True
    )
