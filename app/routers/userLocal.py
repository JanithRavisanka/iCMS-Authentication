import os
from datetime import datetime

from boto3 import client, resource
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, Body, UploadFile, File, Response, HTTPException
from starlette.responses import JSONResponse

# from app.config.config import Config
from app.models.changePassword import ChangePassword
from app.utils.auth import get_current_user

load_dotenv()

aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
aws_default_region = os.getenv('AWS_DEFAULT_REGION')
cognito_pool_id = os.getenv('AWS_COGNITO_USER_POOL_ID')
cognito_app_client_id = os.getenv('AWS_COGNITO_CLIENT_ID')
s3_bucket_name = os.getenv('AWS_S3_BUCKET')
dynamodb_user_logs = os.getenv('DYNAMODB_USER_LOGS_TABLE')

user_router = APIRouter()

# Create a new boto3 client
cognito_client = client('cognito-idp')
dynamodb = resource(
    'dynamodb',
    region_name=aws_default_region,
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)
table = dynamodb.Table(dynamodb_user_logs)


async def log_to_dynamodb(username: str, action: str, is_success: bool):
    current_time = datetime.utcnow().isoformat()

    # Check if the user already exists in the table
    try:
        response = table.get_item(Key={'username': username})
    except Exception as e:
        print(f"Error retrieving item: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving item from DynamoDB")

    if 'Item' not in response:
        # User does not exist, create a new item
        try:
            table.put_item(
                Item={
                    'username': username,
                    # 'creation': {
                    #     'created_by': username,
                    #     'created_time': current_time
                    # },
                    'events': [{
                        'action': action,
                        'is_success': is_success,
                        'time': current_time
                    }]
                }
            )
        except Exception as e:
            print(f"Error creating item: {e}")
            raise HTTPException(status_code=500, detail="Error creating item in DynamoDB")
    else:
        # User exists, update the events list
        try:
            response = table.update_item(
                Key={'username': username},
                UpdateExpression="SET creation.created_by = :cb, creation.created_time = :ct, events = list_append(events, :new_event)",
                ExpressionAttributeValues={
                    ':cb': username,
                    ':ct': current_time,
                    ':new_event': [{
                        'action': action,
                        'is_success': is_success,
                        'time': current_time
                    }]
                },
                ReturnValues="UPDATED_NEW"
            )
        except Exception as e:
            print(f"Error updating item: {e}")
            raise HTTPException(status_code=500, detail="Error updating item in DynamoDB")

    return response


# Helper function to upload file to S3
async def upload_file_to_s3(file: UploadFile, user):
    key = f"{user.username}/{user.username.split('@')[0]}x.png"
    file_content = await file.read()
    s3_client = client('s3')
    s3_client.put_object(
        Bucket=s3_bucket_name,
        Key=key,
        Body=file_content
    )
    return key


# Helper function to update Cognito user attributes
def update_cognito_user_attributes(username: str, attributes: list):
    cognito_client.admin_update_user_attributes(
        UserPoolId=cognito_pool_id,
        Username=username,
        UserAttributes=attributes
    )


# Helper function to get user attributes from Cognito
def get_cognito_user_attributes(username: str):
    return cognito_client.admin_get_user(
        UserPoolId=cognito_pool_id,
        Username=username
    )['UserAttributes']


@user_router.get("/open")
async def open_route():
    return {"message": "This is an open route"}


@user_router.get("/me")
async def read_users_me(current_user=Depends(get_current_user)):
    return current_user


@user_router.post("/uploadProfileImage")
async def upload_profile_image(file: UploadFile = File(...), user=Depends(get_current_user)):
    try:
        key = await upload_file_to_s3(file, user)
        profile_image_url = f"https://{s3_bucket_name}.s3.{aws_default_region}.amazonaws.com/{key}"
        update_cognito_user_attributes(user.username, [
            {
                'Name': 'custom:profile_image',
                'Value': profile_image_url
            }
        ])
        return {"message": "Image uploaded successfully"}
    except Exception as e:
        return {"message": str(e)}


@user_router.get("/getUserProfileData")
async def get_user_profile_data(user=Depends(get_current_user), response=Response):
    attributes_list = get_cognito_user_attributes(user.username)
    # Convert list of attributes to a dictionary
    data = {attr['Name']: attr['Value'] for attr in attributes_list}
    # Add the username to the dictionary
    data['username'] = user.username

    headers = {
        "cache-control": "no-cache",
        "content-type": "application/json"
    }
    return JSONResponse(content=data, headers=headers)


# Helper function to set new password using Cognito client.change_password
def set_new_password(username: str, previous_password: str, proposed_password: str, access_token: str):
    response = cognito_client.change_password(
        PreviousPassword=previous_password,
        ProposedPassword=proposed_password,
        AccessToken=access_token
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return {"success": True}


# change password route
@user_router.post("/changePassword")
async def change_password(change_password: ChangePassword, user=Depends(get_current_user)):
    try:
        set_new_password(user.username, change_password.PreviousPassword, change_password.ProposedPassword,
                         change_password.AccessToken)
        log_response = await log_to_dynamodb(user.username, 'Change Password: Own password', True)
        return {"message": "Password changed successfully"}
    except Exception as e:
        log_response = await log_to_dynamodb(user.username, 'Change Password: Own password', False)
        raise HTTPException(status_code=500, detail=str(e))


@user_router.post("/editUserProfile")
async def edit_user_profile(email: str = Body(...), phone_number: str = Body(...), user=Depends(get_current_user)):
    update_cognito_user_attributes(user.username, [
        {
            'Name': 'email',
            'Value': email
        },
        {
            'Name': 'custom:phone_number',
            'Value': phone_number
        }
    ])
    return {"message": "Profile updated successfully"}
