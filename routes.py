from fastapi import APIRouter, Request, HTTPException, Header
import requests
from config import AUTH_SERVICE_URL, BOOK_SERVICE_URL, ORDER_SERVICE_URL
from utils import verify_jwt_token

router = APIRouter()


@router.post("/login")
async def login(request: Request):
    data = await request.json()
    response = requests.post(f"{AUTH_SERVICE_URL}/login", json=data)
    return response.json()


@router.post("/register")
async def register(request: Request):
    data = await request.json()
    response = requests.post(f"{AUTH_SERVICE_URL}/register", json=data)
    return response.json()


@router.api_route("/livros/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_books(
    request: Request,
    path: str,
    authorization: str = Header(None)
):
    url = f"{BOOK_SERVICE_URL}/livros/{path}"
    body = await request.body()

    response = requests.request(
        method=request.method,
        url=url,
        headers={"Content-Type": request.headers.get("Content-Type")},
        data=body
    )
    return response.json()


@router.api_route("/pedidos/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_orders(
    request: Request,
    path: str,
    authorization: str = Header(None)
):
    url = f"{ORDER_SERVICE_URL}/pedidos/{path}"
    body = await request.body()

    response = requests.request(
        method=request.method,
        url=url,
        headers={"Content-Type": request.headers.get("Content-Type")},
        data=body
    )
    return response.json()
