from pydantic import BaseModel, Field


class CommandRequest(BaseModel):
    command: str = Field(min_length=2, max_length=500)
    authorized: bool = False


class CommandResponse(BaseModel):
    intent: str
    tool: str
    summary: str
    data: dict
    safety_note: str | None = None
