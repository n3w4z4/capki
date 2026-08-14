from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from capki.api.deps import get_current_actor
from capki.core.rbac.context import AuthContext
from capki.db.models.audit import ActorType
from capki.db.session import get_db
from capki.services import csr_service
from capki.services.audit_service import log_action

router = APIRouter(prefix="/csr", tags=["csr"])


class GenerateCsrRequest(BaseModel):
    common_name: str
    organization_name: str | None = None
    sans: list[str] = []
    passphrase: str | None = None


class GenerateCsrResponse(BaseModel):
    private_key_pem: str
    csr_pem: str
    encrypted: bool


@router.post("/generate", response_model=GenerateCsrResponse)
def generate_csr(
    payload: GenerateCsrRequest,
    db: Session = Depends(get_db),
    actor: AuthContext = Depends(get_current_actor),
):
    """Any authenticated user can call this — generating a key pair carries
    no privilege by itself; only using the resulting CSR to actually get a
    certificate issued is gated (by cert:issue / cert:request, enforced on
    those endpoints). Nothing here is persisted; see services/csr_service.py.

    If `passphrase` is set, the returned private key PEM is encrypted
    (PKCS#8, AES) with it — the passphrase itself is never stored or
    logged, same as the key."""
    try:
        private_key_pem, csr_pem = csr_service.generate_key_and_csr(
            common_name=payload.common_name,
            organization_name=payload.organization_name,
            sans=payload.sans,
            passphrase=payload.passphrase,
        )
    except csr_service.CsrGenerationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    log_action(
        db,
        actor_type=ActorType.USER,
        actor_user_id=actor.user_id,
        action="csr.generate",
        detail={"common_name": payload.common_name, "encrypted": bool(payload.passphrase)},
    )
    return GenerateCsrResponse(
        private_key_pem=private_key_pem, csr_pem=csr_pem, encrypted=bool(payload.passphrase)
    )
