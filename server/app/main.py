from fastapi import FastAPI, Request
from .api import users, messages
import os

PREFIX = os.getenv("PREFIX")


lithium = FastAPI()


lithium.include_router(users.router, prefix=PREFIX + "/user", tags=["Users"])
lithium.include_router(messages.router, prefix=PREFIX + "/msg", tags=["Messages"])


@lithium.get(PREFIX)
async def root():
    return {"message": "Welcome to Lithium, real private messenger"}
