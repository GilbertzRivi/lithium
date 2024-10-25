from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel

from app.api.utils import (
    verify_token,
    autodelete_token,
    create_token,
    autodelete_message,
)

from app.database.models import User, Message
from app.database.session import get_async_session

router = APIRouter()

# Pydantic models for request and response handling


class BaseMessage(BaseModel):
    content: str
    recepient_handler: str
    sender_handler: str


class SendMessage(BaseModel):
    content: str
    recepient_handler: str
    sender_handler: str
    token: str


class GetMessages(BaseModel):
    token: str
    handler: str


# Endpoint to send a message to a specific user
@router.post("/send-message/", status_code=status.HTTP_201_CREATED)
async def send_message(
    data: SendMessage, session: AsyncSession = Depends(get_async_session)
):

    handler = await verify_token(data.token, session)

    if handler != data.sender_handler:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token or handler"
        )
    await autodelete_token(data.token, 0, session)

    query = select(User).where(User.handler == data.recepient_handler)
    result = await session.execute(query)
    recepient = result.scalars().first()

    query = select(User).where(User.handler == data.sender_handler)
    result = await session.execute(query)
    sender = result.scalars().first()

    if not recepient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    new_message = Message(
        content=data.content.encode(),
        recepient_id=recepient.id,
        sender_id=sender.id,
    )

    await session.add(new_message)
    await session.commit()

    new_token = await create_token(data.sender_handler, session)

    return {"msg": "Message sent", "token": new_token}


# Endpoint to fetch all messages received by a specific user
@router.post("/get-messages/", status_code=status.HTTP_200_OK)
async def get_received_messages(
    data: GetMessages, session: AsyncSession = Depends(get_async_session)
):

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
        raise HTTPException(status_code=404, detail="User not found")

    query = select(Message).where(Message.recepient_id == user.id)
    result = await session.execute(query)
    messages = result.scalars().all()

    new_token = await create_token(data.handler, session)
    messages_formatted = {
        "messages": [
            BaseMessage(
                content=message.content.decode(),
                sender_handler=message.sender.handler,
                recepient_handler=message.recepient.handler,
            )
            for message in messages
        ],
        "token": new_token,
    }

    for message in messages:
        await autodelete_message(message.id, 0, session)

    return messages_formatted
