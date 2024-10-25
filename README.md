# currently in development

to start the API, create .env file with those variables:
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

then run ``docker compose up`` in the main directory, then run
```
docker exec -it <container-name> /bin/sh
cd app && python3 -m database.rebuild
````

# API Endpoint Documentation
Change url.xyz for your domain, and change lithium for the prefix you have defined in your .env file.

## User Endpoints (`url.xyz/lithium/auth/`)

1. **Register User**
   - **Endpoint**: `POST url.xyz/lithium/auth/register`
   - **Description**: Registers a new user with a unique handler.
   - **Request Body**:
     - `handler` (str): User's unique identifier.
     - `password` (str): Password for the account.
     - `display_name` (str): Display name of the user.
   - **Response**:
     - `msg` (str): Confirmation message.

2. **Login User**
   - **Endpoint**: `POST url.xyz/lithium/auth/login`
   - **Description**: Authenticates a user and generates a token.
   - **Request Body**:
     - `handler` (str): User’s handler.
     - `password` (str): User’s password.
   - **Response**:
     - `token` (str): Generated single-use token.

3. **Change Password**
   - **Endpoint**: `POST url.xyz/lithium/auth/change-password`
   - **Description**: Changes the user’s password.
   - **Request Body**:
     - `handler` (str): User’s handler.
     - `new_password` (str): New password.
     - `token` (str): Single-use token for authentication.
   - **Response**:
     - `msg` (str): Confirmation message.

4. **Get Private Key**
   - **Endpoint**: `POST url.xyz/lithium/auth/get-private-key`
   - **Description**: Retrieves the user’s private key.
   - **Request Body**:
     - `token` (str): Single-use token for authentication.
     - `handler` (str): User’s handler.
     - `password` (str): User’s password for validation.
   - **Response**:
     - `private_key` (str): User’s private key.
     - `token` (str): New token for further requests.

5. **Get Public Key**
   - **Endpoint**: `POST url.xyz/lithium/auth/get-public-key`
   - **Description**: Retrieves the user’s public key.
   - **Request Body**:
     - `handler` (str): User’s handler.
   - **Response**:
     - `public_key` (str): User’s public key.

---

## Messages Endpoints (`url.xyz/lithium/msg/`)

1. **Send Message**
   - **Endpoint**: `POST url.xyz/lithium/msg/send-message/`
   - **Description**: Sends a message from a sender to a specified recipient.
   - **Request Body**:
     - `content` (str): Message content.
     - `recepient_handler` (str): Recipient’s handler.
     - `sender_handler` (str): Sender’s handler.
     - `token` (str): Single-use token for authentication.
   - **Response**:
     - `msg` (str): Confirmation message.
     - `token` (str): New token for further requests.

2. **Get Messages**
   - **Endpoint**: `POST url.xyz/lithium/msg/get-messages/`
   - **Description**: Retrieves all messages received by a specified user.
   - **Request Body**:
     - `token` (str): Single-use token for authentication.
     - `handler` (str): User handler for whom to fetch messages.
   - **Response**:
     - `messages` (list of objects): Contains messages with `content`, `sender_handler`, and `recepient_handler`.
     - `token` (str): New token for further requests.
