from urllib.parse import parse_qs

from fastapi import APIRouter, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

router = APIRouter(prefix="/login", tags=["login"])

USERNAME = "admin"
PASSWORD = "password"


@router.post("")
async def login(request: Request):
    body = (await request.body()).decode()
    form_data = parse_qs(body)

    username = form_data.get("username", [""])[0]
    password = form_data.get("password", [""])[0]

    if username == USERNAME and password == PASSWORD:
        return RedirectResponse(
            url="/dashboard.html",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    return HTMLResponse(
        """
        <h1>Login failed</h1>
        <p>Wrong username or password.</p>
        <a href="/">Try again</a>
        """,
        status_code=status.HTTP_401_UNAUTHORIZED,
    )
