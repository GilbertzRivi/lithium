# currently in development

Lithium is a secure and private messaging application designed to prioritize user privacy and security. This project is built using FastAPI and SQLAlchemy, and it includes functionalities for user management and message exchange with token-based authentication.

## Features

- **User Registration and Authentication**: Secure user registration and login with password hashing and salts.
- **End-to-End Encryption**: Public key support for secure communication.
- **Message Exchange**: Send and retrieve messages privately.
- **Profile Management**: Upload and retrieve profile pictures.
- **Token-Based Authentication**: One-time tokens ensure secure API calls.

## how to start a server

to start the server, create .env file with those variables:
- POSTGRES_USER=*string*
- POSTGRES_PASSWORD=*I recommend at least 32 long string* 
- POSTGRES_DB=*string*
- POSTGRES_HOST=*name of the db container, default lithium-db*
- POSTGRES_PORT=*int, default 5432*
- SECRET_KEY=*at least 32 long random string*
- RESET_PASSWORD_SECRET=*at least 32 long random string*
- VERIFICATION_SECRET=*at least 32 long random string*
- PREFIX=*your desired prefix, for example /lithium, may be empty if not needeed*
- TOKEN_TIMEOUT=*token timeout in seconds*

then run
```shell
docker compose up
docker exec -it <container-name> /bin/sh
cd app && python3 -m database.rebuild
```

## Endpoints Documentation

### User Endpoints

#### Register a New User
- **Endpoint**: `POST /register`
- **Description**: Creates a new user with a unique handler, password, and public key.
- **Request Body**:
  ```json
  {
      "handler": "string",
      "password": "string",
      "display_name": "string",
      "public_key": "string"
  }
  ```
- **Response**:
  ```json
  {
      "msg": "Registration successful"
  }
  ```

#### Login
- **Endpoint**: `POST /login`
- **Description**: Logs in a user and generates a one-time token.
- **Request Body**:
  ```json
  {
      "handler": "string",
      "password": "string"
  }
  ```
- **Response**:
  ```json
  {
      "token": "string"
  }
  ```

#### Change Password
- **Endpoint**: `POST /change-password`
- **Description**: Updates the user’s password after verifying their token.
- **Request Body**:
  ```json
  {
      "handler": "string",
      "new_password": "string",
      "token": "string"
  }
  ```
- **Response**:
  ```json
  {
      "msg": "Password changed successfully"
  }
  ```

#### Get Public Key
- **Endpoint**: `POST /get-public-key`
- **Description**: Retrieves a user’s public key.
- **Request Body**:
  ```json
  {
      "handler": "string"
  }
  ```
- **Response**:
  ```json
  {
      "public_key": "string"
  }
  ```

#### Upload Profile Picture
- **Endpoint**: `POST /pfp`
- **Description**: Uploads or updates a user’s profile picture.
- **Request Parameters**:
  - `token`: String (Form)
  - `handler`: String (Form)
  - `file`: File (JPEG/PNG)
- **Response**:
  ```json
  {
      "msg": "Picture updated",
      "token": "string"
  }
  ```

#### Get Profile Picture
- **Endpoint**: `POST /get-pfp`
- **Description**: Retrieves a user’s profile picture.
- **Request Body**:
  ```json
  {
      "handler": "string"
  }
  ```
- **Response**:
  ```json
  {
      "msg": "Success",
      "data": "base64-encoded-image"
  }
  ```

### Message Endpoints

#### Send Message
- **Endpoint**: `POST /send-message`
- **Description**: Sends a message to a specific user.
- **Request Body**:
  ```json
  {
      "content": "string",
      "recepient_handler": "string",
      "sender_handler": "string",
      "token": "string"
  }
  ```
- **Response**:
  ```json
  {
      "msg": "Message sent",
      "token": "string"
  }
  ```

#### Get Messages
- **Endpoint**: `POST /get-messages`
- **Description**: Retrieves all new messages received by a specific user. After the server sends the request, the messages are permamently delet from the server, so you can collect them only once, for security.
- **Request Body**:
  ```json
  {
      "handler": "string",
      "token": "string"
  }
  ```
- **Response**:
  ```json
  {
      "messages": [
          {
              "content": "string",
              "sender_handler": "string",
              "recepient_handler": "string"
          }
      ],
      "token": "string"
  }
  ```
