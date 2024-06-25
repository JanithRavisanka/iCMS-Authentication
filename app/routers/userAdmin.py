import os
from typing import Annotated, Optional

from boto3 import client
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, Body, Query
from pydantic import BaseModel

from app.config.config import Config
from app.models.newUser import NewUser
from app.utils.admin_functions import sign_up_user, verify_user_email, add_user_to_roles, send_password_email, \
    delete_user_from_cognito, check_user_role, retrieve_all_users, create_permissions_list, create_group, \
    add_users_to_group, add_user_to_cognito_group, retrieve_all_groups, retrieve_users_in_group, retrieve_group_details, \
    process_permissions, retrieve_all_usernames, retrieve_user_details, retrieve_user_groups, retrieve_all_usernames_2, \
    retrieve_group_members, prepare_permissions, update_group, update_user_attributes, get_user_groups, \
    remove_user_from_all_groups, add_user_to_new_groups, disable_user_in_cognito
from app.utils.auth import role_required

load_dotenv()

aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
aws_default_region = os.getenv('AWS_DEFAULT_REGION')

# print(aws_access_key_id)
# print(aws_secret_access_key)

admin_router = APIRouter()
cognito_client = client(
    'cognito-idp',
    region_name=aws_default_region,
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)

ses_client = client('ses', region_name=aws_default_region)


@admin_router.post("/newUser", tags=['Admin-Users'])
async def create_new_user(new_user: Annotated[NewUser, Body()],
                          current_user: Annotated[any, Depends(role_required("Admin"))]):
    response = await sign_up_user(new_user)
    if 'success' not in response:
        return response

    response = await verify_user_email(new_user)
    if 'success' not in response:
        return response

    cognito_client.admin_confirm_sign_up(
        UserPoolId=Config.cognito_pool_id,
        Username=new_user.username
    )

    response = await add_user_to_roles(new_user)
    if 'success' not in response:
        return response

    response = await send_password_email(new_user)
    if 'success' not in response:
        return response

    return {"message": "User created successfully"}


@admin_router.delete("/deleteUser/{username}", tags=['Admin-Users'])
async def delete_user(
        username: str,
        current_user: Annotated[any, Depends(role_required("Admin"))],
):
    permit_roles = ["Admin"]

    if not (set(permit_roles) & set(current_user.roles)):
        return {"message": "You do not have access to this resource"}

    response = await delete_user_from_cognito(username)

    return response


@admin_router.get("/allUsers", tags=['Admin-Users'])
async def get_all_users(current_user: Annotated[any, Depends(role_required("Admin"))]):
    permit_roles = ["Admin"]

    check_role_response = await check_user_role(current_user, permit_roles)
    if 'success' not in check_role_response:
        return check_role_response

    users = await retrieve_all_users()

    return users


class groupPermissions(BaseModel):
    name: str
    value: bool


class User(BaseModel):
    user_name: str


class userGroup(BaseModel):
    group_name: str
    permissions: list[groupPermissions]
    users: Optional[list[User]] = None


@admin_router.post("/createUserGroup", tags=['Roles'])
async def create_user_group(user_group: userGroup = Body(...),
                            current_user=Depends(role_required("Admin"))):
    permissions = await create_permissions_list(user_group)
    response = await create_group(user_group, permissions)
    await add_users_to_group(user_group)
    return response


@admin_router.post("/addUserToGroup", tags=['Admin-Users'])
async def add_user_to_group(username: str = Body(...), group_name: str = Body(...),
                            current_user=Depends(role_required("Admin"))):
    permit_roles = ["Admin"]

    check_role_response = await check_user_role(current_user, permit_roles)
    if 'success' not in check_role_response:
        return check_role_response

    response = await add_user_to_cognito_group(username, group_name)

    return response


# list user groups
@admin_router.get("/UserGroups", tags=['Roles'])
async def list_user_groups(current_user=Depends(role_required("Admin"))):
    permit_roles = ["Admin"]

    check_role_response = await check_user_role(current_user, permit_roles)
    if 'success' not in check_role_response:
        return check_role_response

    groups = await retrieve_all_groups()
    group_data = [{"group_name": group, "number_of_users": await retrieve_users_in_group(group)} for group in groups]

    return group_data


@admin_router.delete("/UserGroups", tags=['Roles'])
async def delete_user_group(group_name: str = Query(...), current_user=Depends(role_required("Admin"))):
    # print(group_name)

    response = cognito_client.delete_group(
        UserPoolId=Config.cognito_pool_id,
        GroupName=group_name
    )
    return response


@admin_router.get("/getGroupDetails", tags=['Roles'])
async def get_group_details(group_name: str = Query(...), current_user=Depends(role_required("Admin"))):
    permit_roles = ["Admin"]

    check_role_response = await check_user_role(current_user, permit_roles)
    if 'success' not in check_role_response:
        return check_role_response

    group_details = await retrieve_group_details(group_name)
    processed_group_details = await process_permissions(group_details)

    return processed_group_details


@admin_router.get("/getAllUsersNames", tags=['Admin-Users'])
async def get_user_names(current_user: Annotated[any, Depends(role_required("Admin"))]):
    permit_roles = ["Admin"]

    check_role_response = await check_user_role(current_user, permit_roles)
    if 'success' not in check_role_response:
        return check_role_response

    usernames = await retrieve_all_usernames()

    return usernames


# gt all user names, emails and their roles
@admin_router.get("/getAllUsers", tags=['Admin-Users'])
async def get_all_users(current_user: Annotated[any, Depends(role_required("Admin"))]):
    permit_roles = ["Admin"]

    check_role_response = await check_user_role(current_user, permit_roles)
    if 'success' not in check_role_response:
        return check_role_response

    usernames = await retrieve_all_usernames_2()

    users = []
    for username in usernames:
        user_email, status = await retrieve_user_details(username)
        groups = await retrieve_user_groups(username)
        users.append({
            "username": username,
            "email": user_email,
            "groups": groups,
            "status": status
        })

    return users


# list members of a group using query parameter group_name
@admin_router.get("/getGroupMembers", tags=['Roles'])
async def get_group_members(group_name: str = Query(...), current_user=Depends(role_required("Admin"))):
    permit_roles = ["Admin"]

    check_role_response = await check_user_role(current_user, permit_roles)
    if 'success' not in check_role_response:
        return check_role_response

    group_members = await retrieve_group_members(group_name)

    return group_members


@admin_router.get('/getUserDetails', tags=['Admin-Users'])
async def get_user_details(username: str = Query(...), current_user=Depends(role_required("Admin"))):
    response = cognito_client.admin_get_user(
        UserPoolId=Config.cognito_pool_id,
        Username=username
    )

    # get user groups and add it to the respone
    user_groups = cognito_client.admin_list_groups_for_user(
        Username=username,
        UserPoolId=Config.cognito_pool_id
    )
    response['roles'] = [{'group_name': group['GroupName'], 'number_of_users': 0} for group in user_groups['Groups']]
    return response


# update the user group attributes
@admin_router.put('/updateRole', tags=['Roles'])
async def update_role(group_name: str = Body(...), permissions: list[groupPermissions] = Body(...),
                      current_user=Depends(role_required("Admin"))):
    permit_roles = ["Admin"]

    check_role_response = await check_user_role(current_user, permit_roles)
    if 'success' not in check_role_response:
        return check_role_response

    prepared_permissions = await prepare_permissions(permissions)
    response = await update_group(group_name, prepared_permissions)

    return response


class UpdateUser(BaseModel):
    username: str
    email: str
    phone_number: str
    roles: list[str]


@admin_router.put("/updateUser", tags=['Admin-Users'])
async def update_user(new_user: Annotated[UpdateUser, Body()],
                      current_user: Annotated[any, Depends(role_required("Admin"))]):
    permit_roles = ["Admin"]

    check_role_response = await check_user_role(current_user, permit_roles)
    if 'success' not in check_role_response:
        return check_role_response

    update_attributes_response = await update_user_attributes(new_user)

    user_groups = await get_user_groups(new_user.username)

    remove_user_response = await remove_user_from_all_groups(new_user.username, user_groups)

    add_user_response = await add_user_to_new_groups(new_user.username, new_user.roles)

    return add_user_response


@admin_router.put("/disableUser", tags=['Admin-Users'])
async def disable_user(username: str = Body(...), current_user=Depends(role_required("Admin"))):
    permit_roles = ["Admin"]

    check_role_response = await check_user_role(current_user, permit_roles)
    if 'success' not in check_role_response:
        return check_role_response

    response = await disable_user_in_cognito(username)

    return response
