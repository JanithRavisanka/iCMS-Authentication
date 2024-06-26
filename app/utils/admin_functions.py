import json
import os

from boto3 import client
from dotenv import load_dotenv

from app.config.config import Config

load_dotenv()

aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
aws_default_region = os.getenv('AWS_DEFAULT_REGION')

cognito_client = client(
    'cognito-idp',
    region_name=aws_default_region,
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)

ses_client = client('ses', region_name=aws_default_region)


async def sign_up_user(new_user):
    try:
        response = cognito_client.sign_up(
            ClientId=Config.cognito_app_client_id,
            Username=new_user.username,
            Password=new_user.password,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': new_user.email
                },
                {
                    'Name': 'custom:phone_number',
                    'Value': new_user.phone_number
                }
            ]
        )
        return {"success": True, "response": response}
    except Exception as e:
        return {"error": f"An error occurred while signing up the user: {e}"}


async def verify_user_email(new_user):
    try:
        cognito_client.admin_update_user_attributes(
            UserPoolId=Config.cognito_pool_id,
            Username=new_user.username,
            UserAttributes=[
                {
                    'Name': 'email_verified',
                    'Value': 'true'
                }
            ]
        )
        return {"success": True}
    except Exception as e:
        return {"error": f"An error occurred while verifying the user email: {e}"}


async def add_user_to_roles(new_user):
    try:
        roles = new_user.roles
        for role in roles:
            cognito_client.admin_add_user_to_group(
                UserPoolId=Config.cognito_pool_id,
                Username=new_user.username,
                GroupName=role
            )
        return {"success": True}
    except Exception as e:
        return {"error": f"An error occurred while adding the user to roles: {e}"}


async def send_password_email(new_user):
    try:
        ses_client.send_email(
            Source='janithravisankax@gmail.com',
            Destination={
                'ToAddresses': [
                    new_user.email,
                ],
            },
            Message={
                'Subject': {
                    'Data': 'Your new password',
                },
                'Body': {
                    'Html': {
                        'Data': f"""
                        <html>
                        <body>
                            <h1>Welcome to iCMS</h1>
                            <p>Hello {new_user.username},</p>
                            <p>Your account has been created successfully.</p>
                            <p>YOur user name is: <b>{new_user.username}</b></p>
                            <p>Your new password is: <b>{new_user.password}</b></p>
                            <p>Please change your password after logging in.</p>
                            <p>Thank you for using iCMS!</p>
                        </body>
                        </html>
                        """,
                    },
                },
            }
        )
        return {"success": True}
    except Exception as e:
        return {"error": f"An error occurred while sending the email: {e}"}


async def delete_user_from_cognito(username: str):
    response = cognito_client.admin_delete_user(
        UserPoolId=Config.cognito_pool_id,
        Username=username
    )
    return response


# get all users
async def check_user_role(current_user, permit_roles):
    if not (set(permit_roles) & set(current_user.roles)):
        return {"message": "You do not have access to this resource"}
    return {"success": True}


async def retrieve_all_users():
    response = cognito_client.list_users(
        UserPoolId=Config.cognito_pool_id
    )
    return [user['Username'] for user in response['Users']]


# create user roles
async def create_permissions_list(user_group):
    permissions = []
    for permission in user_group.permissions:
        permissions.append({
            'Name': permission.name,
            'Value': str(permission.value).lower()
        })
    return permissions


async def create_group(user_group, permissions):
    response = cognito_client.create_group(
        GroupName=user_group.group_name,
        UserPoolId=Config.cognito_pool_id,
        Description=f"{permissions}"
    )
    return response


async def add_users_to_group(user_group):
    for user in user_group.users:
        res = cognito_client.admin_add_user_to_group(
            UserPoolId=Config.cognito_pool_id,
            Username=user.user_name,
            GroupName=user_group.group_name
        )


# add user to a role


async def add_user_to_cognito_group(username: str, group_name: str):
    response = cognito_client.admin_add_user_to_group(
        UserPoolId=Config.cognito_pool_id,
        Username=username,
        GroupName=group_name,
    )
    return response


# groups details
async def retrieve_all_groups():
    response = cognito_client.list_groups(
        UserPoolId=Config.cognito_pool_id
    )
    return [group['GroupName'] for group in response['Groups']]


async def retrieve_users_in_group(group_name):
    response = cognito_client.list_users_in_group(
        UserPoolId=Config.cognito_pool_id,
        GroupName=group_name
    )
    return len(response['Users'])


# group detail
async def retrieve_group_details(group_name):
    response = cognito_client.get_group(
        UserPoolId=Config.cognito_pool_id,
        GroupName=group_name
    )
    return response


async def process_permissions(group_details):
    permission_string = group_details['Group']['Description']
    permission_string = permission_string.replace("'", '"')
    list_of_permissions = json.loads(permission_string)

    group_details['Group']['Permissions'] = list_of_permissions

    # remove description
    del group_details['Group']['Description']

    return group_details


# get user names
async def retrieve_all_usernames():
    response = cognito_client.list_users(
        UserPoolId=Config.cognito_pool_id
    )
    return [{"user_name": user['Username']} for user in response['Users']]


# get all users
async def retrieve_all_usernames_2():
    response = cognito_client.list_users(
        UserPoolId=Config.cognito_pool_id
    )
    return [user['Username'] for user in response['Users']]


async def retrieve_user_details(username):
    user_data = cognito_client.admin_get_user(
        UserPoolId=Config.cognito_pool_id,
        Username=username
    )
    user_email = [attr['Value'] for attr in user_data['UserAttributes'] if attr['Name'] == 'email'][0]
    status = user_data['Enabled']
    return user_email, status


async def retrieve_user_groups(username):
    user_groups = cognito_client.admin_list_groups_for_user(
        Username=username,
        UserPoolId=Config.cognito_pool_id
    )
    return [group['GroupName'] for group in user_groups['Groups']]


# get group members
async def retrieve_group_members(group_name):
    response = cognito_client.list_users_in_group(
        UserPoolId=Config.cognito_pool_id,
        GroupName=group_name
    )
    return response


# update role
async def prepare_permissions(permissions):
    permissions_list = []
    for permission in permissions:
        permissions_list.append({
            'Name': permission.name,
            'Value': str(permission.value).lower()
        })
    return str(permissions_list)


async def update_group(group_name, permissions):
    response = cognito_client.update_group(
        UserPoolId=Config.cognito_pool_id,
        GroupName=group_name,
        Description=permissions
    )
    return response


# update user
async def update_user_attributes(new_user):
    response = cognito_client.admin_update_user_attributes(
        UserPoolId=Config.cognito_pool_id,
        Username=new_user.username,
        UserAttributes=[
            {
                'Name': 'email',
                'Value': new_user.email
            },
            {
                'Name': 'email_verified',
                'Value': 'true'
            },
            {
                'Name': 'custom:phone_number',
                'Value': new_user.phone_number
            }
        ]
    )
    return response


async def get_user_groups(username):
    response = cognito_client.admin_list_groups_for_user(
        Username=username,
        UserPoolId=Config.cognito_pool_id
    )
    return response


async def remove_user_from_all_groups(username, groups):
    response = None
    for group in groups['Groups']:
        response = cognito_client.admin_remove_user_from_group(
            UserPoolId=Config.cognito_pool_id,
            Username=username,
            GroupName=group['GroupName']
        )
    return response


async def add_user_to_new_groups(username, roles):
    response = None
    for role in roles:
        response = cognito_client.admin_add_user_to_group(
            UserPoolId=Config.cognito_pool_id,
            Username=username,
            GroupName=role
        )
    return response


# disable user
async def disable_user_in_cognito(username):
    response = cognito_client.admin_disable_user(
        UserPoolId=Config.cognito_pool_id,
        Username=username
    )
    return response


# enable user
async def check_user_disabled(username):
    response = cognito_client.admin_get_user(
        UserPoolId=Config.cognito_pool_id,
        Username=username
    )
    return response


async def enable_user_in_cognito(username):
    response = cognito_client.admin_enable_user(
        UserPoolId=Config.cognito_pool_id,
        Username=username
    )
    return response


# get user permissions
async def process_group_descriptions(groups):
    for group in groups['Groups']:
        group['Description'] = eval(group['Description'])
    return [group['Description'] for group in groups['Groups']]


async def extract_permissions(permissions_list):
    permissions = []
    for permission in permissions_list:
        for perm in permission:
            if perm['Value'] == 'true':
                permissions.append(perm['Name'])
    return permissions
