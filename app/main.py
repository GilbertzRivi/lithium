from fastapi import FastAPI
from .api import users, messages
import os

PREFIX = os.getenv("PREFIX")


lithium = FastAPI()

# Include the users router
lithium.include_router(users.router, prefix=PREFIX + "/auth", tags=["Users"])
lithium.include_router(messages.router, prefix=PREFIX + "/msg", tags=["Messages"])


# Root endpoint
@lithium.get(PREFIX)
async def root():
    return {"message": "Welcome to Lithium, real private messenger"}
