from fastapi import HTTPException, status
from sqlalchemy.future import select
from datetime import datetime, timedelta
from app.database.models import Token, Message
import asyncio
import jwt
import os

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"


async def autodelete_token(token: str, delay: int, session):
    await asyncio.sleep(delay)
    token = await session.execute(select(Token).where(Token.token == token))
    token = token.scalars().first()
    if token:
        await session.delete(token)
        await session.commit()


async def autodelete_message(message_id: str, delay: int, session):
    await asyncio.sleep(delay)
    message = await session.execute(select(Message).where(Message.id == message_id))
    message = message.scalars().first()
    if message:
        await session.delete(message)
        await session.commit()


# Utility function to create JWT token
async def create_token(handler: str, session):
    expire = datetime.now() + timedelta(minutes=10)
    payload = {"sub": handler, "exp": expire}
    value = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    token = Token(token=value)
    session.add(token)
    await session.commit()
    return value


# Utility function to decode JWT token
async def verify_token(token: str, session):
    query = select(Token).where(Token.token == token)
    result = await session.execute(query)
    dbtoken = result.scalars().first()

    if not dbtoken:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No such token",
        )
    else:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload.get("sub")
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired"
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )
