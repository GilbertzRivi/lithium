from fastapi import (
    APIRouter,
    HTTPException,
    BackgroundTasks,
    UploadFile,
    Depends,
    File,
    Form,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.database.session import get_async_session
from app.database.models import User
from passlib.context import CryptContext
from pydantic import BaseModel
import os
import base64

from app.api.utils import autodelete_token, verify_token, create_token


TOKEN_TIMEOUT = int(os.getenv("TOKEN_TIMEOUT"))
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserRegister(BaseModel):
    handler: str
    password: str
    display_name: str
    public_key: str


class UserLogin(BaseModel):
    handler: str
    password: str


class ChangePassword(BaseModel):
    handler: str
    new_password: str
    token: str


class GetPublic(BaseModel):
    handler: str


class GetImage(BaseModel):
    handler: str


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(
    user_data: UserRegister, session: AsyncSession = Depends(get_async_session)
):
    query = select(User).where(User.handler == user_data.handler)
    result = await session.execute(query)
    existing_user = result.scalars().first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Handler already taken"
        )

    new_user = User(handler=user_data.handler, display_name=user_data.display_name)
    new_user.set_password(user_data.password)
    new_user.public_key = user_data.public_key.encode()

    session.add(new_user)
    await session.commit()
    return {"msg": "Registration sucessfull"}


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

    token = await create_token(user.handler, session)
    bg_task.add_task(autodelete_token, token, TOKEN_TIMEOUT, session)
    user.single_use_token = token
    await session.commit()

    return {"token": token}


@router.post("/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    password_data: ChangePassword, session: AsyncSession = Depends(get_async_session)
):
    handler = await verify_token(password_data.token, session)

    if handler != password_data.handler:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token or handler"
        )
    await autodelete_token(password_data.token, 0, session)

    query = select(User).where(User.handler == password_data.handler)
    result = await session.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    user.set_password(password_data.new_password)
    user.single_use_token = None
    await session.commit()

    return {"msg": "Password changed successfully"}


@router.post("/get-public-key", status_code=status.HTTP_200_OK)
async def get_keys(data: GetPublic, session: AsyncSession = Depends(get_async_session)):

    query = select(User).where(User.handler == data.handler)
    result = await session.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    public_key = user.public_key

    return {"public_key": public_key}


@router.post("/pfp", status_code=status.HTTP_200_OK)
async def upload_image(
    token: str = Form(),
    handler: str = Form(),
    file: UploadFile = File(),
    session: AsyncSession = Depends(get_async_session),
):
    verified_handler = await verify_token(token, session)

    if verified_handler != handler:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token or handler"
        )
    await autodelete_token(token, 0, session)

    query = select(User).where(User.handler == verified_handler)
    result = await session.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if file.content_type not in ["image/jpeg", "image/png"]:
        raise HTTPException(status_code=400, detail="Invalid file type")

    image_data = await file.read()
    user.pfp = image_data
    await session.commit()

    new_token = await create_token(verified_handler, session)

    return {"msg": "Picture updated", "token": new_token}


@router.post("/get-pfp", status_code=status.HTTP_200_OK)
async def get_image(
    data: GetImage,
    session: AsyncSession = Depends(get_async_session),
):

    query = select(User).where(User.handler == data.handler)
    result = await session.execute(query)
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    if not user.pfp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Image not found"
        )

    encoded_image = base64.b64encode(user.pfp).decode("utf-8")

    return {"msg": "Success", "data": encoded_image}
