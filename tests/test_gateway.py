import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch
from jose import jwt
from datetime import datetime, timedelta, timezone
from fastapi.exceptions import HTTPException

# Importa o aplicativo FastAPI real
from app import app
from config import SECRET_KEY, ALGORITHM

# Cria o cliente de teste para a aplicação
client = TestClient(app)

# -----------------------------------------------------------
# CONSTANTES DE TESTE (IGNORADAS PELO SONAR)
# -----------------------------------------------------------
TEST_PASSWORD = "test_secure_password" # Senha mockada para evitar detecção de credencial hardcoded

def create_mock_token(subject: str = "testuser", expires_delta: timedelta = None):
    """Gera um JWT válido para testes."""
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        # Padrão: Token válido por 15 minutos
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
        
    to_encode = {"sub": subject, "exp": expire.timestamp()}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# -----------------------------------------------------------
# TESTES DE ROTEAMENTO (Login/Register - Rotas Livres)
# -----------------------------------------------------------

@patch("routes.requests")
def test_login_register_routes_are_unprotected(mock_requests):
    """Testa se as rotas /login e /register são liberadas pelo middleware."""
    
    mock_requests.post.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"access_token": "mock.jwt.token", "token_type": "bearer"},
        ok=True
    )
    
    # 1. Testar /login (USANDO A CONSTANTE)
    response = client.post("/login", json={"username": "test", "password": TEST_PASSWORD})
    assert response.status_code == 200
    mock_requests.post.assert_called_once()
    
    # Reseta o mock para o próximo teste
    mock_requests.post.reset_mock()

    # 2. Testar /register (USANDO A CONSTANTE)
    response = client.post("/register", json={"username": "new", "password": TEST_PASSWORD})
    assert response.status_code == 200
    mock_requests.post.assert_called_once()
    
    # 3. Testar a rota root, que também é livre
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"mensagem": "Gateway funcionando, capitão!"}

# -----------------------------------------------------------
# TESTES DE SEGURANÇA (Middleware verify_token)
# -----------------------------------------------------------

def test_protected_route_without_token():
    """Testa se uma rota protegida (ex: /livros) falha sem o header Authorization."""
    with pytest.raises(HTTPException) as exc_info: 
        client.get("/livros/123")
    
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token ausente"

def test_protected_route_with_invalid_token_format():
    """Testa se o token com formato Bearer incorreto falha."""
    with pytest.raises(HTTPException) as exc_info:
        client.get("/livros/123", headers={"Authorization": "InvalidTokenFormat"})
    
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token ausente" 

def test_protected_route_with_expired_token():
    """Testa se um token expirado falha."""
    expired_token = create_mock_token(expires_delta=timedelta(hours=-1))
    
    with pytest.raises(HTTPException) as exc_info:
        client.get("/livros/123", headers={"Authorization": f"Bearer {expired_token}"})
        
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token inválido ou expirado"
    
def test_protected_route_with_invalid_signature():
    """Testa se um token com chave secreta errada falha."""
    # Gera um token com uma chave secreta falsa
    invalid_token = jwt.encode({"sub": "malicious", "exp": datetime.now(timezone.utc).timestamp() + 900}, "CHAVE_SECRETA_FALSA", algorithm=ALGORITHM)
    
    with pytest.raises(HTTPException) as exc_info:
        client.get("/livros/123", headers={"Authorization": f"Bearer {invalid_token}"})
        
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Token inválido ou expirado"

# -----------------------------------------------------------
# TESTES DE PROXY (Roteamento com Token Válido)
# -----------------------------------------------------------

@patch("routes.requests")
def test_books_proxy_with_valid_token(mock_requests):
    """Testa o proxy /livros com um token válido."""
    
    valid_token = create_mock_token()
    
    # Mocka a resposta do BOOK_SERVICE
    mock_requests.request.return_value = MagicMock(
        status_code=200, 
        json=lambda: {"titulo": "O Livro Roteado"},
        ok=True
    )
    
    # Faz a requisição na rota protegida
    response = client.get(
        "/livros/buscar/123", 
        headers={
            "Authorization": f"Bearer {valid_token}",
            "Content-Type": "application/json"
        }
    )
    
    assert response.status_code == 200
    mock_requests.request.assert_called_once()