"""Offline scenario lab: seeded synthetic attack scenarios for automated tests and score calibration. NOT part of the deployed application.

Nothing in `backend/`, `frontend/` or `deploy/` imports this package, and the Docker image does not contain it. The lab's API
routes are mounted only when LAB_MODE=true is set explicitly (the tests and `python -m ml.calibrate_scoring` do that), and the
backend refuses to start in production with LAB_MODE on. Everything generated here is flagged synthetic and is never a live
security incident; production security events come only from real requests.
"""
