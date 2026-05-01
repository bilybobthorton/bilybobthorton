"""ML model management — status, reload, and synthetic training trigger."""
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from api.auth.dependencies import get_current_user
from api.models.scan import User
from engine.ml.model import get_model, reload_model, _MODEL_PATH

router = APIRouter(prefix="/api/v1/ml", tags=["ml"])


def _require_enterprise(user: User = Depends(get_current_user)) -> User:
    if user.tier != "enterprise":
        raise HTTPException(status_code=403, detail="Requires Enterprise tier")
    return user


@router.get("/status")
async def model_status(current_user: User = Depends(get_current_user)):
    """Return current ML model status and metadata."""
    model = get_model()
    model_size = _MODEL_PATH.stat().st_size if _MODEL_PATH.exists() else 0
    return {
        "trained": model.trained,
        "threshold": model.threshold,
        "model_path": str(_MODEL_PATH),
        "model_size_bytes": model_size,
        "model_exists": _MODEL_PATH.exists(),
    }


@router.post("/reload")
async def reload(current_user: User = Depends(_require_enterprise)):
    """Reload the ML model from disk (after retraining offline)."""
    model = reload_model()
    return {"status": "reloaded", "trained": model.trained}


@router.post("/train/synthetic")
async def train_synthetic(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(_require_enterprise),
):
    """
    Generate a synthetic dev model in the background.
    Use for testing only — train on real data with the CLI for production.
    """
    def _do_train():
        from engine.ml.trainer import _generate_synthetic_model
        _generate_synthetic_model(_MODEL_PATH)
        reload_model()

    background_tasks.add_task(_do_train)
    return {"status": "training_started", "note": "Synthetic model — not for production use"}
