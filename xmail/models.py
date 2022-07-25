from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, FileUrl, StrictStr, conlist


class Email(BaseModel):
    sender: EmailStr
    to: EmailStr
    cc: conlist(EmailStr, unique_items=True)
    body: StrictStr
    sent_at: datetime = Field(default_factory=datetime.utcnow)
    received_at: datetime
    attachments: conlist(FileUrl)
    tags: conlist(StrictStr, unique_items=True)
    deleted: bool = False


SCHEMA = {"*": Email}
