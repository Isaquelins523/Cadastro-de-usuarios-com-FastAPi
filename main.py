from fastapi import FastAPI, Depends, HTTPException, status
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi import Form
import psycopg2
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# Chave secreta para o JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Configurações do cliente
CLIENT_ID = "seu_client_id"
CLIENT_SECRET = "seu_client_secret"


# Criptografia para senhas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Definir o sistema de login OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


app = FastAPI()


# Modelo de usuário no banco de dados (simulado)
fake_users_db = {
    "user1": {
        "username": "user1",
        "full_name": "User One",
        "email": "user1@example.com",
        "hashed_password": pwd_context.hash("password123"),
        "disabled": False,
    }
}

# Modelo de token
class Token(BaseModel):
    access_token: str
    token_type: str

# Modelo de usuário
class User(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

# Classe de formulário de autenticação com client_id e client_secret
class OAuth2PasswordRequestFormWithClient(OAuth2PasswordRequestForm):
    grant_type: str = Form("password")  
    client_id: str = Form(...)
    client_secret: str = Form(...)


# Função para verificar se a senha está correta
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Função para obter usuário do "banco de dados"
def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

# Função para autenticar o usuário
def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Função para criar o token JWT
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Endpoint para login e geração do token
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestFormWithClient = Depends()):
    # Verifique o client_id e client_secret
    if form_data.client_id != CLIENT_ID or form_data.client_secret != CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid client credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


# Função para obter o usuário a partir do token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username)
    if user is None:
        raise credentials_exception
    return user

# Função para verificar se o usuário está ativo
async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Rota protegida que exige autenticação
@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

def get_connection():
    return psycopg2.connect(host='db', database='clients',user='postgres', password='232425')

class User(BaseModel):
    name:str
    username:str
    password:str


@app.post("/create", response_model=dict)
def create_client(user: User, current_user: User = Depends(get_current_active_user)):
    conn = get_connection()
    cursor = conn.cursor()
    

    # Inserir o cliente no banco de dados
    cursor.execute("""
        INSERT INTO clients (name, username, password) 
        VALUES (%s, %s, %s)
    """, (user.name, user.username, user.password))

    conn.commit()
    cursor.close()
    conn.close()

    return {"mensagem": f"Cliente {user.name} criado com sucesso!"}




@app.get("/findall")
def find_all_clients():
    conn = get_connection()
    cursor = conn.cursor()

    # Selecionar todos os clientes
    cursor.execute("SELECT name, username, password FROM clients")
    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    # Converter para um formato utilizável pela API
    clients = [{"name": row[0], "username": row[1], "password": row[2]} for row in rows]
    
    return {"clients": clients}


@app.put("/update/{username}", response_model=dict)
def update_client(username: str, updated_user: User, current_user: User = Depends(get_current_active_user)):
    conn = get_connection()
    cursor = conn.cursor()

    # Atualizar o cliente no banco de dados
    cursor.execute("""
        UPDATE clients
        SET name = %s, username = %s, password = %s
        WHERE username = %s
    """, (updated_user.name, updated_user.username, updated_user.password, username))

    conn.commit()
    cursor.close()
    conn.close()

    return {"mensagem": f"Cliente {username} atualizado com sucesso!"}



@app.delete("/delete/{username}", response_model=dict)
def delete_client(username: str, current_user: User = Depends(get_current_active_user)):
    conn = get_connection()
    cursor = conn.cursor()

    # Remover o cliente do banco de dados
    cursor.execute("DELETE FROM clients WHERE username = %s", (username,))

    conn.commit()
    cursor.close()
    conn.close()

    return {"mensagem": f"Cliente {username} excluído com sucesso!"}
