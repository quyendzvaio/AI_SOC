from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import create_access_token, generate_otp, hash_otp, hash_password, verify_otp, verify_password
from app.db import get_session
from app.models import OtpPurpose, OtpToken, User
from app.schemas import AuthOut, LoginIn, RegisterIn, ResendOtpIn, UserOut, VerifyOtpIn
from app.services.runtime_config import load_runtime_config
from app.services.smtp_mail import send_smtp_email

router = APIRouter(prefix="/auth", tags=["auth"])


def user_out(user: User) -> UserOut:
    return UserOut(
        id=user.id, email=user.email, role=user.role.value,
        is_email_verified=user.is_email_verified,
        notification_email=user.notification_email,
        is_notification_email_verified=user.is_notification_email_verified,
    )


@router.post("/register", response_model=AuthOut, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterIn, session: AsyncSession = Depends(get_session)) -> AuthOut:
    existing = await session.scalar(select(User).where(User.email == payload.email.lower()))
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(email=payload.email.lower(), password_hash=hash_password(payload.password))
    session.add(user)
    await session.flush()

    otp = generate_otp()
    session.add(
        OtpToken(
            user_id=user.id,
            otp_hash=hash_otp(otp),
            purpose=OtpPurpose.register,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=get_settings().otp_ttl_minutes),
        )
    )
    await session.commit()
    try:
        config = await load_runtime_config(session)
        send_smtp_email(
            user.email,
            "[AI-SOC] OTP đăng ký tài khoản",
            f"OTP xác thực đăng ký của bạn là: {otp}\nMã có hiệu lực trong {get_settings().otp_ttl_minutes} phút.",
            config,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Gửi OTP qua SMTP thất bại: {str(exc)}") from exc
    return AuthOut(user=user_out(user), otp_required=True)


@router.post("/verify-otp", response_model=AuthOut)
async def verify_registration_otp(payload: VerifyOtpIn, session: AsyncSession = Depends(get_session)) -> AuthOut:
    user = await session.scalar(select(User).where(User.email == payload.email.lower()))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    token = await session.scalar(
        select(OtpToken)
        .where(OtpToken.user_id == user.id, OtpToken.purpose == payload.purpose, OtpToken.consumed_at.is_(None))
        .order_by(OtpToken.expires_at.desc())
    )
    now = datetime.now(timezone.utc)
    if not token or token.expires_at < now or not verify_otp(payload.otp, token.otp_hash):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    token.consumed_at = now
    user.is_email_verified = True
    await session.commit()
    access_token = create_access_token(str(user.id), {"role": user.role.value})
    return AuthOut(token=access_token, user=user_out(user))


@router.post("/login", response_model=AuthOut)
async def login(payload: LoginIn, session: AsyncSession = Depends(get_session)) -> AuthOut:
    user = await session.scalar(select(User).where(User.email == payload.email.lower()))
    now = datetime.now(timezone.utc)
    if not user:
        raise HTTPException(status_code=401, detail="Sai thông tin đăng nhập")
    if user.locked_until and user.locked_until > now:
        raise HTTPException(status_code=423, detail="Sai quá nhiều lần, tài khoản bị khóa tạm thời")
    if not user.password_hash:
        raise HTTPException(status_code=400, detail="Tài khoản này chưa có mật khẩu local hợp lệ")
    if not verify_password(payload.password, user.password_hash):
        user.failed_login_count += 1
        if user.failed_login_count >= 3:
            user.locked_until = now + timedelta(minutes=15)
            user.failed_login_count = 0
        await session.commit()
        raise HTTPException(status_code=401, detail="Sai thông tin đăng nhập")
    if not user.is_email_verified:
        raise HTTPException(status_code=403, detail="Email is not verified")

    otp = generate_otp()
    session.add(
        OtpToken(
            user_id=user.id,
            otp_hash=hash_otp(otp),
            purpose=OtpPurpose.login,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=get_settings().otp_ttl_minutes),
        )
    )
    user.failed_login_count = 0
    user.locked_until = None
    await session.commit()
    try:
        config = await load_runtime_config(session)
        send_smtp_email(
            user.email,
            "[AI-SOC] OTP đăng nhập",
            f"OTP đăng nhập của bạn là: {otp}\nMã có hiệu lực trong {get_settings().otp_ttl_minutes} phút.",
            config,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Gửi OTP qua SMTP thất bại: {str(exc)}") from exc
    return AuthOut(user=user_out(user), otp_required=True)


@router.post("/resend-otp", response_model=AuthOut)
async def resend_otp(payload: ResendOtpIn, session: AsyncSession = Depends(get_session)) -> AuthOut:
    user = await session.scalar(select(User).where(User.email == payload.email.lower()))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    otp = generate_otp()
    session.add(
        OtpToken(
            user_id=user.id,
            otp_hash=hash_otp(otp),
            purpose=OtpPurpose(payload.purpose),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=get_settings().otp_ttl_minutes),
        )
    )
    await session.commit()
    try:
        config = await load_runtime_config(session)
        send_smtp_email(
            user.email,
            "[AI-SOC] OTP xác thực",
            f"OTP của bạn là: {otp}\nMã có hiệu lực trong {get_settings().otp_ttl_minutes} phút.",
            config,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Gửi OTP qua SMTP thất bại: {str(exc)}") from exc
    return AuthOut(user=user_out(user), otp_required=True)
