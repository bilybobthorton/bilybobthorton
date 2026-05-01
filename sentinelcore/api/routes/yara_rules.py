"""
YARA rule management API.

Free tier: read-only access to built-in rules.
Pro/Enterprise: create, update, delete custom rules + live compile validation.
"""
import logging
import uuid
from typing import List, Optional

import yara
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select, update, delete

from api.auth.dependencies import get_current_user
from api.database import get_session
from api.models.scan import User
from api.models.yara_rule import YaraRule

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/yara", tags=["yara"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    name: str
    description: Optional[str] = None
    rule_text: str
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def name_no_spaces(cls, v: str) -> str:
        if " " in v:
            raise ValueError("Rule name cannot contain spaces")
        return v

    @field_validator("rule_text")
    @classmethod
    def validate_yara(cls, v: str) -> str:
        try:
            yara.compile(source=v)
        except yara.SyntaxError as e:
            raise ValueError(f"YARA syntax error: {e}")
        return v


class RuleUpdate(BaseModel):
    description: Optional[str] = None
    rule_text: Optional[str] = None
    enabled: Optional[bool] = None

    @field_validator("rule_text")
    @classmethod
    def validate_yara(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            try:
                yara.compile(source=v)
            except yara.SyntaxError as e:
                raise ValueError(f"YARA syntax error: {e}")
        return v


class RuleResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    rule_text: str
    enabled: bool
    is_builtin: bool
    hit_count: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class ValidateRequest(BaseModel):
    rule_text: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/rules", response_model=List[RuleResponse])
async def list_rules(
    enabled_only: bool = False,
    current_user: User = Depends(get_current_user),
):
    """List all YARA rules visible to this user (built-ins + their own)."""
    async with get_session() as session:
        q = select(YaraRule).where(
            YaraRule.is_builtin.is_(True) | (YaraRule.user_id == current_user.id)
        )
        if enabled_only:
            q = q.where(YaraRule.enabled.is_(True))
        q = q.order_by(YaraRule.is_builtin.desc(), YaraRule.created_at.desc())
        result = await session.execute(q)
        rules = result.scalars().all()

    return [_serialize_rule(r) for r in rules]


@router.get("/rules/{rule_id}", response_model=RuleResponse)
async def get_rule(rule_id: str, current_user: User = Depends(get_current_user)):
    rule = await _fetch_rule(rule_id, current_user)
    return _serialize_rule(rule)


@router.post("/rules", response_model=RuleResponse, status_code=201)
async def create_rule(
    body: RuleCreate,
    current_user: User = Depends(get_current_user),
):
    """Create a custom YARA rule. Requires Pro or Enterprise tier."""
    _require_pro(current_user)

    async with get_session() as session:
        # Check name uniqueness for this user
        existing = await session.execute(
            select(YaraRule).where(YaraRule.name == body.name)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail=f"Rule name '{body.name}' already exists")

        rule = YaraRule(
            id=uuid.uuid4(),
            user_id=current_user.id,
            name=body.name,
            description=body.description,
            rule_text=body.rule_text,
            enabled=body.enabled,
            is_builtin=False,
        )
        session.add(rule)
        await session.commit()
        await session.refresh(rule)

    logger.info("YARA rule created: %s by user %s", body.name, current_user.id)
    return _serialize_rule(rule)


@router.patch("/rules/{rule_id}", response_model=RuleResponse)
async def update_rule(
    rule_id: str,
    body: RuleUpdate,
    current_user: User = Depends(get_current_user),
):
    """Update a custom rule. Cannot modify built-in rules."""
    _require_pro(current_user)
    rule = await _fetch_rule(rule_id, current_user)

    if rule.is_builtin:
        raise HTTPException(status_code=403, detail="Cannot modify built-in rules")

    updates = body.model_dump(exclude_none=True)
    if not updates:
        return _serialize_rule(rule)

    async with get_session() as session:
        await session.execute(
            update(YaraRule).where(YaraRule.id == rule.id).values(**updates)
        )
        await session.commit()
        result = await session.execute(select(YaraRule).where(YaraRule.id == rule.id))
        rule = result.scalar_one()

    return _serialize_rule(rule)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: str, current_user: User = Depends(get_current_user)):
    """Delete a custom rule. Cannot delete built-in rules."""
    _require_pro(current_user)
    rule = await _fetch_rule(rule_id, current_user)

    if rule.is_builtin:
        raise HTTPException(status_code=403, detail="Cannot delete built-in rules")

    async with get_session() as session:
        await session.execute(delete(YaraRule).where(YaraRule.id == rule.id))
        await session.commit()


@router.post("/validate")
async def validate_rule(
    body: ValidateRequest,
    current_user: User = Depends(get_current_user),
):
    """Compile-check a YARA rule without saving it. Available to all tiers."""
    try:
        compiled = yara.compile(source=body.rule_text)
        # Count rule names in the compiled ruleset
        rule_names = [r.identifier for r in compiled]
        return {"valid": True, "rule_count": len(rule_names), "rules": rule_names}
    except yara.SyntaxError as e:
        return {"valid": False, "error": str(e)}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_pro(user: User) -> None:
    if user.tier not in ("pro", "enterprise"):
        raise HTTPException(
            status_code=403,
            detail="Custom YARA rules require a Pro or Enterprise plan",
        )


async def _fetch_rule(rule_id: str, user: User) -> YaraRule:
    async with get_session() as session:
        result = await session.execute(
            select(YaraRule).where(
                (YaraRule.id == uuid.UUID(rule_id)) &
                (YaraRule.is_builtin.is_(True) | (YaraRule.user_id == user.id))
            )
        )
        rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


def _serialize_rule(r: YaraRule) -> RuleResponse:
    return RuleResponse(
        id=str(r.id),
        name=r.name,
        description=r.description,
        rule_text=r.rule_text,
        enabled=r.enabled,
        is_builtin=r.is_builtin,
        hit_count=r.hit_count or "0",
        created_at=r.created_at.isoformat() if r.created_at else "",
        updated_at=r.updated_at.isoformat() if r.updated_at else "",
    )
