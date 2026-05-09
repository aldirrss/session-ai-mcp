from pydantic import BaseModel, Field


class SessionCreateInput(BaseModel):
    title: str = Field(..., description="Short human-readable title for the session.")
    content: str = Field(
        default="",
        description="Initial content — project context, goals, decisions, next steps.",
    )


class SessionWriteInput(BaseModel):
    session_id: str = Field(..., description="UUID of the session to update.")
    content: str = Field(
        ...,
        description=(
            "Full updated content. Always include all previous decisions and context — "
            "this overwrites the entire session content."
        ),
    )


class SessionReadInput(BaseModel):
    session_id: str = Field(..., description="UUID of the session to read.")


class SessionListInput(BaseModel):
    show_archived: bool = Field(default=False, description="Include archived sessions.")
