from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, UserSession
from ..schemas import LoginIn, RegisterIn, UserOut
from ..security.auth import (
    clear_session_cookies,
    create_session,
    csrf_token_for,
    get_current_session,
    hash_password,
    onboarding_complete,
    rate_limit,
    verify_password,
)
from ..services.document_ops import purge_ephemeral_documents

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _user_out(user: User, sess: UserSession | None) -> UserOut:
    return UserOut(
        id=user.id, email=user.email, created_at=user.created_at,
        onboarding_complete=onboarding_complete(user.preferences),
        csrf_token=csrf_token_for(sess.token_hash) if sess else None,
    )


@router.post("/register", response_model=UserOut, status_code=201, dependencies=[Depends(rate_limit("auth"))])
def register(body: RegisterIn, response: Response, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists")
    user = User(email=email, password_hash=hash_password(body.password))
    db.add(user)
    db.commit()
    sess = create_session(db, user, response)
    return _user_out(user, sess)


@router.post("/login", response_model=UserOut, dependencies=[Depends(rate_limit("auth"))])
def login(body: LoginIn, response: Response, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == body.email.lower().strip()))
    ok = verify_password(user.password_hash if user else None, body.password)
    if not user or not ok or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    sess = create_session(db, user, response)
    return _user_out(user, sess)


@router.post("/logout", status_code=204)
def logout(response: Response, sess: UserSession = Depends(get_current_session), db: Session = Depends(get_db)):
    user_id = sess.user_id
    db.delete(sess)
    db.commit()
    # Documents kept only for the session (history saving disabled) are removed at logout.
    purge_ephemeral_documents(db, user_id=user_id)
    clear_session_cookies(response)
    response.status_code = 204
    return response


@router.get("/me", response_model=UserOut)
def me(sess: UserSession = Depends(get_current_session)):
    return _user_out(sess.user, sess)
