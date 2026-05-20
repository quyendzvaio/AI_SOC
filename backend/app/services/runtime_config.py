from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import RuntimeSetting
from app.services.crypto import decrypt_value


async def load_runtime_config(session: AsyncSession) -> dict[str, str | None]:
    result = await session.execute(select(RuntimeSetting))
    config: dict[str, str | None] = {}
    for setting in result.scalars():
        config[setting.key] = decrypt_value(setting.value_encrypted) if setting.is_secret else setting.value_public
    return config

