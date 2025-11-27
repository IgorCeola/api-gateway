from jose import jwt, JWTError
from fastapi import HTTPException, Request, status
from config import SECRET_KEY, ALGORITHM

def verify_jwt_token(token: str):
    print("Testando execução!!!!")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado."
        )

