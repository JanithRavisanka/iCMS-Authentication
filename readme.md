# FastAPI User Management

This project is a user management system built with FastAPI. It includes functionalities for user authentication, profile management, and file uploads to AWS S3.

## Features

- User authentication with AWS Cognito
- Profile management (view, edit, upload profile image)
- File uploads to AWS S3
- Logging user actions to DynamoDB

## Requirements

- Python 3.8+
- AWS account with S3 and Cognito setup
- Docker (for containerization)

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/iCSMS-Authentication.git
    cd iCSMS-Authentication
    ```

2. Create a virtual environment and activate it:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the dependencies:
    ```sh
    pip install -r requirements.txt
    ```

4. Set up your AWS credentials and region in the `.env` file:
    ```env
    AWS_ACCESS_KEY_ID=your_access_key_id
    AWS_SECRET_ACCESS_KEY=your_secret_access_key
    AWS_REGION=your_aws_region
    AWS_S3_BUCKET=your_s3_bucket
    AWS_COGNITO_USER_POOL_ID=your_cognito_user_pool_id
    AWS_COGNITO_CLIENT_ID=your_cognito_client_id
    ```

## Running the Application

1. Start the FastAPI server:
    ```sh
    uvicorn app.main:app --reload
    ```

2. The application will be available at `http://localhost:8000`.

## Docker

To run the application using Docker:

1. Build the Docker image:
    ```sh
    docker build -t icsms/icsms-auth:latest .
    ```

2. Start the Docker container:
    ```sh
    docker run -p 8000:8000 --env-file .env icsms/icsms-auth:latest 
    ```

3. The application will be available at `http://localhost:8000`.

## Admin Features

- **User Logs**
  - Endpoint: `/userLogs`
  - Method: `GET`
  - Description: Retrieve user logs within a specified time range.

- **Create New User**
  - Endpoint: `/newUser`
  - Method: `POST`
  - Description: Create a new user.

- **Delete User**
  - Endpoint: `/deleteUser/{username}`
  - Method: `DELETE`
  - Description: Delete a user by username.

- **Get All Users**
  - Endpoint: `/allUsers`
  - Method: `GET`
  - Description: Retrieve all users.

- **Create User Group**
  - Endpoint: `/createUserGroup`
  - Method: `POST`
  - Description: Create a new user group.

- **Add User to Group**
  - Endpoint: `/addUserToGroup`
  - Method: `POST`
  - Description: Add a user to a group.

- **List User Groups**
  - Endpoint: `/UserGroups`
  - Method: `GET`
  - Description: List all user groups.

- **Delete User Group**
  - Endpoint: `/UserGroups`
  - Method: `DELETE`
  - Description: Delete a user group.

- **Get Group Details**
  - Endpoint: `/getGroupDetails`
  - Method: `GET`
  - Description: Get details of a specific group.

- **Get All User Names**
  - Endpoint: `/getAllUsersNames`
  - Method: `GET`
  - Description: Retrieve all user names.

- **Get All Users Data**
  - Endpoint: `/getAllUsers`
  - Method: `GET`
  - Description: Retrieve all user names, emails, and roles.

- **Get Group Members**
  - Endpoint: `/getGroupMembers`
  - Method: `GET`
  - Description: List members of a group.

- **Get User Details**
  - Endpoint: `/getUserDetails`
  - Method: `GET`
  - Description: Get details of a specific user.

- **Update Role**
  - Endpoint: `/updateRole`
  - Method: `PUT`
  - Description: Update the attributes of a user group.

- **Update User**
  - Endpoint: `/updateUser`
  - Method: `PUT`
  - Description: Update user details.

- **Enable User**
  - Endpoint: `/enableUser`
  - Method: `PUT`
  - Description: Enable a user.

- **Disable User**
  - Endpoint: `/disableUser`
  - Method: `PUT`
  - Description: Disable a user.

- **Get User Permissions**
  - Endpoint: `/getUserPermissions/{username}`
  - Method: `GET`
  - Description: Get permissions of a user.

- **Get User Auth Logs**
  - Endpoint: `/userAuthLogs/{username}`
  - Method: `GET`
  - Description: Get authentication events for a user.

- **Set Subscribed Users**
  - Endpoint: `/set_subscribed_users`
  - Method: `POST`
  - Description: Update subscribed users.

- **Get Subscribed Users**
  - Endpoint: `/get_subscribed_users`
  - Method: `GET`
  - Description: Retrieve subscribed users.

- **Get Weights**
  - Endpoint: `/get_weights`
  - Method: `GET`
  - Description: Retrieve weights configuration.

- **Set Weights**
  - Endpoint: `/set_weights`
  - Method: `POST`
  - Description: Update weights configuration.

- **Get Average Actions**
  - Endpoint: `/get_average_actions`
  - Method: `GET`
  - Description: Retrieve average actions configuration.

- **Set Average Actions**
  - Endpoint: `/set_average_actions`
  - Method: `POST`
  - Description: Update average actions configuration.

- **Get Thresholds**
  - Endpoint: `/get_thresholds`
  - Method: `GET`
  - Description: Retrieve thresholds configuration.

- **Set Thresholds**
  - Endpoint: `/set_thresholds`
  - Method: `POST`
  - Description: Update thresholds configuration.

- **Get Rules**
  - Endpoint: `/get_rules`
  - Method: `GET`
  - Description: Retrieve rules configuration.

- **Set Rules**
  - Endpoint: `/set_rules`
  - Method: `POST`
  - Description: Update rules configuration.

## User Features

- **Open Route**
  - Endpoint: `/open`
  - Method: `GET`
  - Description: Access an open route.

- **Read User Profile**
  - Endpoint: `/me`
  - Method: `GET`
  - Description: Retrieve current user profile.

- **Upload Profile Image**
  - Endpoint: `/uploadProfileImage`
  - Method: `POST`
  - Description: Upload a profile image.

- **Get User Profile Data**
  - Endpoint: `/getUserProfileData`
  - Method: `GET`
  - Description: Retrieve user profile data.

- **Change Password**
  - Endpoint: `/changePassword`
  - Method: `POST`
  - Description: Change user password.

- **Edit User Profile**
  - Endpoint: `/editUserProfile`
  - Method: `POST`
  - Description: Edit user profile details.
