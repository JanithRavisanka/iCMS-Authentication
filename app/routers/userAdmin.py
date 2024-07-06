import os
from datetime import datetime
from typing import Annotated, Optional, List

from boto3 import client, resource
from dotenv import load_dotenv
from fastapi import APIRouter, Body, HTTPException, Depends, Query
from pydantic import BaseModel

from app.config.config import Config
from app.models.newUser import NewUser
from app.utils.admin_functions import sign_up_user, verify_user_email, add_user_to_roles, send_password_email, \
    delete_user_from_cognito, retrieve_all_users, create_permissions_list, create_group, \
    add_users_to_group, add_user_to_cognito_group, retrieve_all_groups, retrieve_users_in_group, retrieve_group_details, \
    process_permissions, retrieve_all_usernames, retrieve_group_members, prepare_permissions, update_group, \
    update_user_attributes, get_user_groups, \
    remove_user_from_all_groups, add_user_to_new_groups, disable_user_in_cognito, process_group_descriptions, \
    extract_permissions, check_user_disabled, enable_user_in_cognito, retrieve_all_data
from app.utils.auth import get_current_user

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

dynamodb = resource(
    'dynamodb',
    region_name=aws_default_region,
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)
table = dynamodb.Table('icsms-user-activity-logs')


class LogEntry(BaseModel):
    action: str
    is_success: bool
    time: str


class UserLogs(BaseModel):
    username: str
    creation: dict
    events: List[LogEntry]


# async def log_to_dynamodb(username: str, action: str, is_success: bool):
#     current_time = datetime.utcnow().isoformat()

#     # Check if the user already exists in the table
#     try:
#         response = table.get_item(Key={'username': username})
#     except Exception as e:
#         print(f"Error retrieving item: {e}")
#         raise HTTPException(status_code=500, detail="Error retrieving item from DynamoDB")

#     if 'Item' not in response:
#         # User does not exist, create a new item
#         try:
#             table.put_item(
#                 Item={
#                     'username': username,
#                     # 'creation': {
#                     #     'created_by': username,
#                     #     'created_time': current_time
#                     # },
#                     'events': [{
#                         'action': action,
#                         'is_success': is_success,
#                         'time': current_time
#                     }]
#                 }
#             )
#         except Exception as e:
#             print(f"Error creating item: {e}")
#             raise HTTPException(status_code=500, detail="Error creating item in DynamoDB")
#     else:
#         # User exists, update the events list
#         try:
#             response = table.update_item(
#                 Key={'username': username},
#                 UpdateExpression="SET creation.created_by = :cb, creation.created_time = :ct, events = list_append(events, :new_event)",
#                 ExpressionAttributeValues={
#                     ':cb': username,
#                     ':ct': current_time,
#                     ':new_event': [{
#                         'action': action,
#                         'is_success': is_success,
#                         'time': current_time
#                     }]
#                 },
#                 ReturnValues="UPDATED_NEW"
#             )
#         except Exception as e:
#             print(f"Error updating item: {e}")
#             raise HTTPException(status_code=500, detail="Error updating item in DynamoDB")

#     return response

async def log_to_dynamodb(username: str, action: str, is_success: bool, newuser: str = None):
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

    elif newuser:
        # User exists, update the events list
        try:
            table.put_item(
                Item={
                    'username': newuser,
                    'creation': {
                        'created_time': current_time,
                        'created_by': username
                    },
                    'events': []
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
                UpdateExpression="SET events = list_append(events, :new_event)",
                ExpressionAttributeValues={
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


ses_client = client('ses', region_name=aws_default_region)


class groupPermissions(BaseModel):
    name: str
    value: bool


class User(BaseModel):
    user_name: str


class userGroup(BaseModel):
    group_name: str
    permissions: list[groupPermissions]
    users: Optional[list[User]] = None


class UpdateUser(BaseModel):
    username: str
    email: str
    phone_number: str
    roles: list[str]


def check_permissions(current_user, required_permissions):
    if not (set(required_permissions) & set(current_user.permissions)):
        return {"message": "You do not have access to this resource"}
    return {"success": True}


@admin_router.get("/userLogs", response_model=List[LogEntry], tags=['Admin-Logs'])
async def get_user_logs(username: str, start_time: str, end_time: str):
    try:
        start_time_dt = datetime.fromisoformat(start_time)
        end_time_dt = datetime.fromisoformat(end_time)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid time format. Use ISO format.")

    try:
        response = table.get_item(
            Key={'username': username}
        )
    except Exception as e:
        print(f"Error retrieving item: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving logs from DynamoDB")

    if 'Item' not in response:
        raise HTTPException(status_code=404, detail="No logs found for the given username")

    user_item = response['Item']
    filtered_events = []

    if 'events' in user_item:
        for event in user_item['events']:
            event_time = datetime.fromisoformat(event['time'])
            if start_time_dt <= event_time <= end_time_dt:
                filtered_events.append({
                    "action": event['action'],
                    "is_success": event['is_success'],
                    "time": event['time']
                })

    if not filtered_events:
        raise HTTPException(status_code=404, detail="No logs found for the given time range")

    return filtered_events


@admin_router.post("/newUser", tags=['Admin-Users'])
async def create_new_user(new_user: Annotated[NewUser, Body()],
                          current_user: Annotated[any, Depends(get_current_user)]):
    # check if the user has the required permissions
    required_permissions = ["Add User"]
    if 'success' not in check_permissions(current_user, required_permissions):
        return HTTPException(status_code=403, detail="You do not have access to this resource")

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

    log_response = await log_to_dynamodb(current_user.username, f"{required_permissions[0]}: {new_user.username}", True,
                                         new_user.username)

    return {"message": "User created successfully"}


@admin_router.delete("/deleteUser/{username}", tags=['Admin-Users'])
async def delete_user(
        username: str,
        current_user: Annotated[any, Depends(get_current_user)],
):
    required_permissions = ["Delete User"]
    if 'success' not in check_permissions(current_user, required_permissions):
        log_response = await log_to_dynamodb(current_user.username,
                                             f"{required_permissions[0]}: {username}, Not authorized", False)
        return HTTPException(status_code=403, detail="You do not have access to this resource")

    response = await delete_user_from_cognito(username)
    print(response)

    if 'success' in response:
        log_action = f"{required_permissions[0]}: {username}"
        is_success = True
    else:
        log_action = f"{required_permissions[0]}: {username}"
        is_success = False

    log_response = await log_to_dynamodb(current_user.username, log_action, is_success)

    return response


@admin_router.get("/allUsers", tags=['Admin-Users'])
async def get_all_users(current_user: Annotated[any, Depends(get_current_user)]):
    print(current_user)
    required_permissions = ["View Users"]
    if 'success' not in check_permissions(current_user, required_permissions):
        log_response = await log_to_dynamodb(current_user.username, f"{required_permissions[0]}: Not authorized", False)
        return HTTPException(status_code=403, detail="You do not have access to this resource")

    try:
        users = await retrieve_all_users()
        log_response = await log_to_dynamodb(current_user.username, f"{required_permissions[0]}: Success", True)
        return users
    except Exception as e:
        log_response = await log_to_dynamodb(current_user.username,
                                             f"{required_permissions[0]}: Failed due to {str(e)}", False)
        raise HTTPException(status_code=500, detail="Internal server error")


@admin_router.post("/createUserGroup", tags=['Roles'])
async def create_user_group(user_group: userGroup = Body(...),
                            current_user=Depends(get_current_user)):
    required_permissions = ["Add Role"]
    if 'success' not in check_permissions(current_user, required_permissions):
        await log_to_dynamodb(current_user.username,
                              f"{required_permissions[0]}: {user_group.group_name}, Not authorized", False)
        return HTTPException(status_code=403, detail="You do not have access to this resource")

    try:
        permissions = await create_permissions_list(user_group)
        response = await create_group(user_group, permissions)
        await add_users_to_group(user_group)
        await log_to_dynamodb(current_user.username, f"{required_permissions[0]}: {user_group.group_name}", True)
        return response
    except Exception as e:
        await log_to_dynamodb(current_user.username,
                              f"{required_permissions[0]}: {user_group.group_name}, Failed due to {str(e)}", False)
        raise HTTPException(status_code=500, detail="Internal server error")


@admin_router.post("/addUserToGroup", tags=['Admin-Users'])
async def add_user_to_group(username: str = Body(...), group_name: str = Body(...),
                            current_user=Depends(get_current_user)):
    required_permissions = ["Add User To Group"]
    if 'success' not in check_permissions(current_user, required_permissions):
        await log_to_dynamodb(current_user.username,
                              f"{required_permissions[0]}: {username} to group: {group_name}, Not authorized", False)
        return HTTPException(status_code=403, detail="You do not have access to this resource")

    try:
        response = await add_user_to_cognito_group(username, group_name)
        await log_to_dynamodb(current_user.username, f"{required_permissions[0]}: {username} to group: {group_name}",
                              True)
        return response
    except Exception as e:
        await log_to_dynamodb(current_user.username,
                              f"{required_permissions[0]}: {username} to group: {group_name}, Error: {str(e)}", False)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# list user groups
@admin_router.get("/UserGroups", tags=['Roles'])
async def list_user_groups(current_user=Depends(get_current_user)):
    action = "View Roles"
    try:
        required_permissions = ["View Roles"]
        if 'success' not in check_permissions(current_user, required_permissions):
            await log_to_dynamodb(current_user.username, action + ": Not authorized", False)
            return HTTPException(status_code=403, detail="You do not have access to this resource")

        groups = await retrieve_all_groups()
        group_data = [{"group_name": group, "number_of_users": await retrieve_users_in_group(group)} for group in
                      groups]
        await log_to_dynamodb(current_user.username, action + ": Success", True)
        return group_data
    except Exception as e:
        await log_to_dynamodb(current_user.username, f"{action}: Failed due to {str(e)}", False)
        raise HTTPException(status_code=500, detail="Internal server error")


@admin_router.delete("/UserGroups", tags=['Roles'])
async def delete_user_group(group_name: str = Query(...), current_user=Depends(get_current_user)):
    required_permissions = ["Delete Role"]
    if 'success' not in check_permissions(current_user, required_permissions):
        await log_to_dynamodb(current_user.username, f"{required_permissions[0]}: {group_name}, Not authorized", False)
        return HTTPException(status_code=403, detail="You do not have access to this resource")

    try:
        response = cognito_client.delete_group(
            UserPoolId=Config.cognito_pool_id,
            GroupName=group_name
        )
        await log_to_dynamodb(current_user.username, f"{required_permissions[0]}: {group_name}", True)
        return response
    except Exception as e:
        await log_to_dynamodb(current_user.username, f"{required_permissions[0]}: {group_name}, Error: {str(e)}", False)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@admin_router.get("/getGroupDetails", tags=['Roles'])
async def get_group_details(group_name: str = Query(...), current_user=Depends(get_current_user)):
    required_permissions = ["View Role"]
    if 'success' not in check_permissions(current_user, required_permissions):
        await log_to_dynamodb(current_user.username, f"View Role: {group_name}, Not authorized", False)
        return HTTPException(status_code=403, detail="You do not have access to this resource")

    try:
        group_details = await retrieve_group_details(group_name)
        processed_group_details = await process_permissions(group_details)
        await log_to_dynamodb(current_user.username, f"View Role: {group_name}, Success", True)
        return processed_group_details
    except Exception as e:
        await log_to_dynamodb(current_user.username, f"View Role: {group_name}, Failed due to {str(e)}", False)
        raise HTTPException(status_code=500, detail="Internal server error")


@admin_router.get("/getAllUsersNames", tags=['Admin-Users'])
async def get_user_names(current_user: Annotated[any, Depends(get_current_user)]):
    required_permissions = ["View Users"]
    if 'success' not in check_permissions(current_user, required_permissions):
        await log_to_dynamodb(current_user.username, "View Users: Not authorized", False)
        return HTTPException(status_code=403, detail="You do not have access to this resource")

    try:
        usernames = await retrieve_all_usernames()
        await log_to_dynamodb(current_user.username, "View Users: Success", True)
        return usernames
    except Exception as e:
        await log_to_dynamodb(current_user.username, f"View Users: Failed due to {str(e)}", False)
        raise HTTPException(status_code=500, detail="Internal server error")


# gt all user names, emails and their roles
@admin_router.get("/getAllUsers", tags=['Admin-Users'])
async def get_all_users(current_user: Annotated[any, Depends(get_current_user)]):
    required_permissions = ["View Users"]
    if 'success' not in check_permissions(current_user, required_permissions):
        await log_to_dynamodb(current_user.username, required_permissions[0] + ": Not authorized", False)
        return HTTPException(status_code=403, detail="You do not have access to this resource")

    try:
        userdata = await retrieve_all_data()
        await log_to_dynamodb(current_user.username, required_permissions[0] + ": Success", True)
        return userdata
    except Exception as e:
        await log_to_dynamodb(current_user.username, f"required_permissions[0]: Failed due to {str(e)}", False)
        raise HTTPException(status_code=500, detail="Internal server error")


# list members of a group using query parameter group_name
@admin_router.get("/getGroupMembers", tags=['Roles'])
async def get_group_members(group_name: str = Query(...), current_user=Depends(get_current_user)):
    required_permissions = ["View Role"]
    try:

        if 'success' not in check_permissions(current_user, required_permissions):
            await log_to_dynamodb(current_user.username, required_permissions[0] + ": Not authorized", False)
            return HTTPException(status_code=403, detail="You do not have access to this resource")

        group_members = await retrieve_group_members(group_name)
        await log_to_dynamodb(current_user.username, required_permissions[0] + ": Success", True)
        return group_members
    except Exception as e:
        await log_to_dynamodb(current_user.username, f"{required_permissions[0]}: Failed due to {str(e)}", False)
        raise HTTPException(status_code=500, detail="Internal server error")


@admin_router.get('/getUserDetails', tags=['Admin-Users'])
async def get_user_details(username: str = Query(...), current_user=Depends(get_current_user)):
    required_permissions = ["View User"]
    if 'success' not in check_permissions(current_user, required_permissions):
        await log_to_dynamodb(current_user.username, f"View User: {username}, Not authorized", False)
        return HTTPException(status_code=403, detail="You do not have access to this resource")

    try:
        response = cognito_client.admin_get_user(
            UserPoolId=Config.cognito_pool_id,
            Username=username
        )

        # get user groups and add it to the response
        user_groups = cognito_client.admin_list_groups_for_user(
            Username=username,
            UserPoolId=Config.cognito_pool_id
        )
        response['roles'] = [{'group_name': group['GroupName'], 'number_of_users': 0} for group in
                             user_groups['Groups']]

        await log_to_dynamodb(current_user.username, f"View User: {username}, Success", True)
        return response
    except Exception as e:
        await log_to_dynamodb(current_user.username, f"View User: {username}, Failed due to {str(e)}", False)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# update the user group attributes
@admin_router.put('/updateRole', tags=['Roles'])
async def update_role(group_name: str = Body(...), permissions: list[groupPermissions] = Body(...),
                      current_user=Depends(get_current_user)):
    action = "Edit Role"
    try:
        required_permissions = ["Edit Role"]
        if 'success' not in check_permissions(current_user, required_permissions):
            await log_to_dynamodb(current_user.username, f"{action}: {group_name}, Not authorized", False)
            return HTTPException(status_code=403, detail="You do not have access to this resource")

        prepared_permissions = await prepare_permissions(permissions)
        response = await update_group(group_name, prepared_permissions)
        await log_to_dynamodb(current_user.username, f"{action}: {group_name}, {prepared_permissions}", True)
        return response
    except Exception as e:
        await log_to_dynamodb(current_user.username, f"{action}: {group_name}, Failed due to {str(e)}", False)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@admin_router.put("/updateUser", tags=['Admin-Users'])
async def update_user(new_user: Annotated[UpdateUser, Body()],
                      current_user: Annotated[any, Depends(get_current_user)]):
    action = "Edit User"
    try:
        required_permissions = ["Edit User"]
        if 'success' not in check_permissions(current_user, required_permissions):
            await log_to_dynamodb(current_user.username, f"{action}: {new_user.username}, Not authorized", False)
            return HTTPException(status_code=403, detail="You do not have access to this resource")

        update_attributes_response = await update_user_attributes(new_user)
        if 'success' not in update_attributes_response:
            await log_to_dynamodb(current_user.username, f"{action}: {new_user.username}, Failed to update attributes",
                                  False)
            return HTTPException(status_code=500, detail="Failed to update user attributes")

        user_groups = await get_user_groups(new_user.username)
        remove_user_response = await remove_user_from_all_groups(new_user.username, user_groups)
        if 'success' not in remove_user_response:
            await log_to_dynamodb(current_user.username, f"{action}: {new_user.username}, Failed to remove from groups",
                                  False)
            return HTTPException(status_code=500, detail="Failed to remove user from groups")

        add_user_response = await add_user_to_new_groups(new_user.username, new_user.roles)
        if 'success' not in add_user_response:
            await log_to_dynamodb(current_user.username, f"{action}: {new_user.username}, Failed to add to new groups",
                                  False)
            return HTTPException(status_code=500, detail="Failed to add user to new groups")

        await log_to_dynamodb(current_user.username, f"{action}: {new_user.username}, Success", True)
        return {"message": "User updated successfully"}
    except Exception as e:
        await log_to_dynamodb(current_user.username, f"{action}: {new_user.username}, Failed due to {str(e)}", False)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# enable user
@admin_router.put("/enableUser", tags=['Admin-Users'])
async def enable_user(username: str = Body(...), current_user=Depends(get_current_user)):
    action = "Enable User"
    try:
        required_permissions = ["Enable User"]
        if 'success' not in check_permissions(current_user, required_permissions):
            await log_to_dynamodb(current_user.username, f"{action}: {username}, Not authorized", False)
            return HTTPException(status_code=403, detail="You do not have access to this resource")

        user_status = await check_user_disabled(username)

        if not user_status['Enabled']:
            response = await enable_user_in_cognito(username)
            await log_to_dynamodb(current_user.username, f"{action}: {username}, Success", True)
            return response
        else:
            await log_to_dynamodb(current_user.username, f"{action}: {username}, User already enabled", True)
            return {"message": "User is already enabled"}
    except Exception as e:
        await log_to_dynamodb(current_user.username, f"{action}: {username}, Failed due to {str(e)}", False)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@admin_router.put("/disableUser", tags=['Admin-Users'])
async def disable_user(username: str = Body(...), current_user=Depends(get_current_user)):
    action = "Disable User"
    try:
        required_permissions = ["Disable User"]
        if 'success' not in check_permissions(current_user, required_permissions):
            await log_to_dynamodb(current_user.username, f"{action}: {username}, Not authorized", False)
            return HTTPException(status_code=403, detail="You do not have access to this resource")

        response = await disable_user_in_cognito(username)
        await log_to_dynamodb(current_user.username, f"{action}: {username}, Success", True)
        return response
    except Exception as e:
        await log_to_dynamodb(current_user.username, f"{action}: {username}, Failed due to {str(e)}", False)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# get permissions of a user
@admin_router.get("/getUserPermissions/{username}", tags=['Roles'])
async def get_user_permissions(username: str, current_user=Depends(get_current_user)):
    action = "Get User Permissions"
    try:
        user_groups = await get_user_groups(username)
        permissions_list = await process_group_descriptions(user_groups)
        permissions = await extract_permissions(permissions_list)
        return permissions
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# get auth events for a user from cognito using client.admin_list_user_auth_events
@admin_router.get("/userAuthLogs/{username}", tags=['Admin-Logs'])
def get_auth_events(username):
    # Initialize the Cognito Identity Provider client
    auth_events = []
    try:
        # Retrieve authentication events for the specified user
        response = cognito_client.admin_list_user_auth_events(
            UserPoolId=Config.cognito_pool_id,
            Username=username,
            MaxResults=20  # Adjust as needed
        )
        # return response['AuthEvents']
        for auth_event in response['AuthEvents']:
            auth_events.append(
                {
                    "action": auth_event['EventType'],
                    "is_success": True if (auth_event['EventResponse'] == "Pass" or auth_event[
                        'EventType'] == "SignUp") else False,
                    "time": auth_event["CreationDate"],
                    "event_data": auth_event["EventContextData"]

                }
            )

        return auth_events

    except Exception as e:
        print(f"Error retrieving auth events: {e}")
        return []
