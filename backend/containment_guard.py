"""Request guard for the containment endpoints: administrators only, rate-limited, and every refusal is audited."""
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.event_service import write_audit
from backend.rate_limit import containment_limiter
from backend.security import AuthContext, get_auth, resolve_ip


def containment_admin(request: Request, auth: AuthContext = Depends(get_auth), db: Session = Depends(get_db)) -> AuthContext:
    ip = resolve_ip(request, auth.employee)
    if not auth.is_admin:
        write_audit(db, "containment_unauthorized", actor_id=auth.employee.id, ip=ip,
                    details={"method": request.method, "path": request.url.path, "role": auth.employee.role})
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Security administrator role required")
    wait = containment_limiter.check(auth.employee.id)
    if wait:
        write_audit(db, "containment_rate_limited", actor_id=auth.employee.id, ip=ip,
                    details={"path": request.url.path, "retry_after_seconds": wait})
        db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many containment requests; slow down and retry",
                            headers={"Retry-After": str(wait)})
    return auth
