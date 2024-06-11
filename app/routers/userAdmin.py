import os
from typing import Annotated

from boto3 import client
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, Body, Query
from pydantic import BaseModel

from app.config.config import Config
from app.models.adminUser import DeleteUser
from app.models.newUser import NewUser
from app.utils.auth import role_required

load_dotenv()

aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
aws_default_region = os.getenv('AWS_DEFAULT_REGION')

print(aws_access_key_id)
print(aws_secret_access_key)

admin_router = APIRouter()
cognito_client = client(
    'cognito-idp',
    region_name=aws_default_region,
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)


@admin_router.get("/admin")
async def admin_route(user=Depends(role_required("Admin"))):
    return {"message": "Hello Admin", "user": user}


@admin_router.post("/newUser")
async def create_new_user(new_user: Annotated[NewUser, Body()]):
    response = cognito_client.admin_create_user(
        UserPoolId=Config.cognito_pool_id,
        Username=new_user.username,
        TemporaryPassword=new_user.password,
        UserAttributes=[
            {
                'Name': 'email',
                'Value': new_user.email
            },
        ]

    )
    return response


@admin_router.post("/deleteUser")
async def delete_user(
        delete_user: Annotated[DeleteUser, Body()],
        current_user: Annotated[any, Depends(role_required("Admin"))]
):
    permit_roles = ["Admin"]
    print(delete_user)
    print(current_user.roles)
    if not (set(permit_roles) & set(current_user.roles)):
        return {"message": "You do not have access to this resource"}
    response = cognito_client.admin_delete_user(
        UserPoolId=Config.cognito_pool_id,
        Username=delete_user.username
    )
    return response


@admin_router.get("/allUsers")
async def get_all_users(current_user: Annotated[any, Depends(role_required("Admin"))]):
    permit_roles = ["Admin"]
    if not (set(permit_roles) & set(current_user.roles)):
        return {"message": "You do not have access to this resource"}
    response = cognito_client.list_users(
        UserPoolId=Config.cognito_pool_id
    )
    # only get the username
    return [user['Username'] for user in response['Users']]


class groupPermissions(BaseModel):
    name: str
    value: bool


class User(BaseModel):
    user_name: str


class userGroup(BaseModel):
    group_name: str
    permissions: list[groupPermissions]
    users: list[User]


@admin_router.post("/createUserGroup")
async def create_user_group(user_group: userGroup = Body(...),
                            current_user=Depends(role_required("Admin"))):
    response = cognito_client.create_group(
        GroupName=user_group.group_name,
        UserPoolId=Config.cognito_pool_id,
        Description=f"{user_group.permissions}"
    )

    # add users to the group
    for user in user_group.users:
        res = cognito_client.admin_add_user_to_group(
            UserPoolId=Config.cognito_pool_id,
            Username=user.user_name,
            GroupName=user_group.group_name
        )

    return response


@admin_router.post("/addUserToGroup")
async def add_user_to_group(username: str = Body(...), group_name: str = Body(...),
                            current_user=Depends(role_required("Admin"))):
    response = cognito_client.admin_add_user_to_group(
        UserPoolId=Config.cognito_pool_id,
        Username=username,
        GroupName=group_name,
    )

    return response


# list user groups
@admin_router.get("/UserGroups")
async def list_user_groups(current_user=Depends(role_required("Admin"))):
    groups = []
    group_data = []
    response = cognito_client.list_groups(
        UserPoolId=Config.cognito_pool_id
    )
    for group in response['Groups']:
        groups.append(group['GroupName'])

    for group in groups:
        response = cognito_client.list_users_in_group(
            UserPoolId=Config.cognito_pool_id,
            GroupName=group
        )
        group_data.append({"group_name": group, "number_of_users": len(response['Users'])})

    print(group_data)

    return group_data


@admin_router.delete("/UserGroups")
async def delete_user_group(group_name: str = Query(...), current_user=Depends(role_required("Admin"))):
    print(group_name)

    response = cognito_client.delete_group(
        UserPoolId=Config.cognito_pool_id,
        GroupName=group_name
    )
    return response


@admin_router.get("/getGroupDetails")
async def get_group_details(group_name: str = Query(...), current_user=Depends(role_required("Admin"))):
    response = cognito_client.get_group(
        UserPoolId=Config.cognito_pool_id,
        GroupName=group_name
    )
    return response


@admin_router.get("/getAllUsersNames")
async def get_user_names(current_user=Depends(role_required("Admin"))):
    response = cognito_client.list_users(
        UserPoolId=Config.cognito_pool_id
    )
    return [{"user_name": user['Username']} for user in response['Users']]


# gt all user names, emails and their roles
@admin_router.get("/getAllUsers")
async def get_all_users(current_user=Depends(role_required("Admin"))):
    response = cognito_client.list_users(
        UserPoolId=Config.cognito_pool_id
    )
    users_name = [user['Username'] for user in response['Users']]

    # for every user in the list of users, get their email and roles
    users = []
    for user in users_name:
        user_data = cognito_client.admin_get_user(
            UserPoolId=Config.cognito_pool_id,
            Username=user
        )
        user_email = [attr['Value'] for attr in user_data['UserAttributes'] if attr['Name'] == 'email'][0]

        # get user groups
        user_groups = cognito_client.admin_list_groups_for_user(
            Username=user,
            UserPoolId=Config.cognito_pool_id
        )
        users.append({
            "username": user,
            "email": user_email,
            "groups": [group['GroupName'] for group in user_groups['Groups']]
        })

    return users


# list members of a group using query parameter group_name
@admin_router.get("/getGroupMembers")
async def get_group_members(group_name: str = Query(...), current_user=Depends(role_required("Admin"))):
    response = cognito_client.list_users_in_group(
        UserPoolId=Config.cognito_pool_id,
        GroupName=group_name
    )
    return response
