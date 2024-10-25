from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.database.session import get_async_session
from app.database.models import User
from passlib.context import CryptContext
from pydantic import BaseModel
import os

from app.api.utils import autodelete_token, verify_token, create_token


TOKEN_TIMEOUT = int(os.getenv("TOKEN_TIMEOUT"))
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Pydantic models
class UserRegister(BaseModel):
    handler: str
    password: str
    display_name: str


class UserLogin(BaseModel):
    handler: str
    password: str


class ChangePassword(BaseModel):
    handler: str
    new_password: str
    token: str


class GetPrivate(BaseModel):
    token: str
    handler: str
    password: str


class GetPublic(BaseModel):
    handler: str


# Register a new user
@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserRegister, session: AsyncSession = Depends(get_async_session)
):
    # Check if user with the same handler exists
    query = select(User).where(User.handler == user_data.handler)
    result = await session.execute(query)
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Handler already taken"
        )

    # Create a new user
    new_user = User(handler=user_data.handler, display_name=user_data.display_name)
    new_user.set_password(user_data.password)
    new_user.generate_keys(user_data.password)

    session.add(new_user)
    await session.commit()
    return {"msg": "User created successfully"}


# Login user and generate a token
@router.post("/login", status_code=status.HTTP_200_OK)
async def login_user(
    user_data: UserLogin,
    bg_task: BackgroundTasks,
    session: AsyncSession = Depends(get_async_session),
):
    query = select(User).where(User.handler == user_data.handler)
    result = await session.execute(query)
    user = result.scalars().first()

    if not user or not user.verify_password(user_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid handler or password",
        )

    # Generate a single-use token
    token = await create_token(user.handler, session)
    bg_task.add_task(autodelete_token, token, TOKEN_TIMEOUT, session)
    user.single_use_token = token
    await session.commit()

    return {"token": token}


# Change password
@router.post("/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    password_data: ChangePassword, session: AsyncSession = Depends(get_async_session)
):
    # Verify token and get the user
    handler = await verify_token(password_data.token, session)

    if handler != password_data.handler:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token or handler"
        )

    # Fetch user
    query = select(User).where(User.handler == password_data.handler)
    result = await session.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Change password and invalidate token
    user.set_password(password_data.new_password)
    user.single_use_token = None
    await session.commit()

    return {"msg": "Password changed successfully"}


# Change password
@router.post("/get-private-key", status_code=status.HTTP_200_OK)
async def get_keys(
    data: GetPrivate, session: AsyncSession = Depends(get_async_session)
):
    # Verify token and get the user
    handler = await verify_token(data.token, session)

    if handler != data.handler:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token or handler"
        )
    await autodelete_token(data.token, 0, session)

    # Fetch user
    query = select(User).where(User.handler == data.handler)
    result = await session.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Change password and invalidate token
    private_key = user.get_private_key(data.password)

    new_token = await create_token(user.handler, session)

    return {"private_key": private_key, "token": new_token}


# Change password
@router.post("/get-public-key", status_code=status.HTTP_200_OK)
async def get_keys(data: GetPublic, session: AsyncSession = Depends(get_async_session)):

    # Fetch user
    query = select(User).where(User.handler == data.handler)
    result = await session.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    public_key = user.public_key

    return {"public_key": public_key}
