from fastapi import FastAPI, Request, HTTPException
from jose import jwt, JWTError
from config import SECRET_KEY, ALGORITHM
from routes import router

app = FastAPI(title="API Gateway - Livraria")

@app.middleware("http")
async def verify_token(request: Request, call_next):
    print("Testando execução") 
    if request.url.path in ["/login", "/register", "/"]:
        return await call_next(request)

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente")

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        request.state.user = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

    response = await call_next(request)
    return response

app.include_router(router)

@app.get("/")
def root():
    return {"mensagem": "Gateway funcionando, capitão!"}
