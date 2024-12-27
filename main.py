# Importación de dependencias necesarias
from fastapi import FastAPI, HTTPException, Depends, status
from typing import List, Optional
from pydantic import BaseModel
from jose import JWTError, jwt  # Para manejo de JWT (JSON Web Tokens)
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm  # Para OAuth2 y formularios
from passlib.context import CryptContext  # Para manejo de contraseñas
from random import randrange
from enum import Enum

# Configuración para el manejo de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")  # Utiliza bcrypt para el hash de contraseñas

# Configuración del sistema de autenticación JWT
SECRET_KEY = "mi_clave_secreta"  # Clave secreta para la firma de los JWT
ALGORITHM = "HS256"  # Algoritmo de cifrado para el JWT
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Tiempo de expiración del token en minutos

app = FastAPI()  # Creación de la aplicación FastAPI

# Instanciación de OAuth2 para obtener el token en el endpoint /token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Funciones para manejar contraseñas
def get_password_hash(password: str) -> str:
    """Función para generar el hash de la contraseña"""
    return pwd_context.hash(password)

class Role(str, Enum):
    admin = "admin"
    support = "support"
    user = "user"

# Base de datos simulada (diccionario con usuarios)
fake_users_db = {
    1: {
        "id": 1,
        "username": "usuario1",
        "hashed_password": get_password_hash("password123"),
        "disabled": False,
        "role": Role.admin,
    },
    2: {
        "id": 2,
        "username": "usuario2",
        "hashed_password": get_password_hash("password456"),
        "disabled": False,
        "role": Role.support
    },
    3: {
        "id": 3,
        "username": "usuario3",
        "hashed_password": get_password_hash("password789"),
        "disabled": False,
        "role": Role.user,
    },
}



# Pydantic models para validación de datos
class UserBase(BaseModel):
    username: str  # El nombre de usuario es obligatorio
    disabled: Optional[bool] = False  # Indica si el usuario está deshabilitado, por defecto es False
    role: Role = Role.user  # Definir el rol, por defecto es 'user'

class UserCreate(UserBase):
    password: str  # Para crear un nuevo usuario, además del username, se requiere la contraseña

class UserUpdate(UserBase):
    username: Optional[str] = None
    password: Optional[str] = None  # Puede actualizarse la contraseña
    disabled: Optional[bool] = None  # Puede actualizarse si el usuario está deshabilitado
    role: Optional[Role] = None  # Permitir modificar el rol, si es necesario

class UserInDB(UserBase):
    id: int  # ID único del usuario
    hashed_password: str  # Contraseña hasheada

# Funciones para manejar contraseñas
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Función para verificar si una contraseña es válida comparando la versión en texto plano con la versión hasheada"""
    return pwd_context.verify(plain_password, hashed_password)


# Función para crear el token de acceso JWT
def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})

    # Asegurarse de que "sub" sea un string
    if "sub" in to_encode and isinstance(to_encode["sub"], int):
        to_encode["sub"] = str(to_encode["sub"])  # Convertir a string
    
    # Agregar el campo "role" al payload del token
    if "role" not in to_encode:
        raise ValueError("El rol debe estar presente en los datos del usuario para crear el token")

    # Generar el JWT
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Función para decodificar el token JWT y obtener el user_id
def decode_access_token(token: str) -> tuple[int, str]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        user_role: str = payload.get("role")  # Extraer el rol del payload
        
        if user_id is None or user_role is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token inválido: user_id o role no encontrado",
            )
        
        return int(user_id), user_role  # Devolver el user_id y el role
    
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
        )


# Función para obtener un usuario de la base de datos simulada
def get_user(db, user_id: int, user_role: str):
    """Busca un usuario en la base de datos simulada por su ID y verifica permisos"""
    user = db.get(user_id)  # Buscar al usuario por su ID
    
    if user is None:
        return None  # Si no se encuentra el usuario, retornar None
    
    # Si el usuario no es un administrador, solo puede ver su propio perfil
    if user_role != "admin" and user["id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para acceder a los datos de otro usuario"
        )
    
    return UserInDB(**user)  # Retornar los datos del usuario en formato UserInDB
 # Retornar los datos del usuario en formato UserInDB


# Endpoint para obtener el token de acceso
@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # Busca el usuario por su username en la base de datos simulada
    user = next((u for u in fake_users_db.values() if u["username"] == form_data.username), None)
    if user is None or not verify_password(form_data.password, user["hashed_password"]):  # Verificar contraseña
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generar el token de acceso, ahora incluyendo el rol del usuario
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user["id"]), "role": user["role"]},  # Incluir el rol del usuario en los datos
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=UserInDB)
def read_users_me(token: str = Depends(oauth2_scheme)):
    """Obtiene la información del usuario actual a partir del token."""
    # Decodificar el token para obtener el user_id y el rol
    user_id, user_role = decode_access_token(token)  # Accede directamente a los dos valores de la tupla

    
    # Buscar el usuario en la base de datos simulada
    user = get_user(fake_users_db, user_id,user_role)
    if user is None or user.disabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado o deshabilitado",
        )

    # Aquí puedes verificar el rol si es necesario (por ejemplo, si el usuario es administrador)

    return user

@app.get("/users/{user_id}", response_model=UserInDB)
def get_user_by_id(user_id: int, token: str = Depends(oauth2_scheme)):
    """Obtiene un usuario por su ID, solo accesible para administradores"""
    # Decodificar el token y obtener el ID del usuario autenticado y su rol
    user_id_from_token, user_role = decode_access_token(token)
    print("User ID from token:", user_id_from_token)
    print("Role from token:", user_role)

    # Verificar que el rol sea administrador
    if user_role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para acceder a esta información"
        )

    # Buscar el usuario por su ID
    user = fake_users_db.get(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado"
        )

    return user  # Retornar la información del usuario


@app.get("/users", response_model=List[UserInDB])
def get_users(token: str = Depends(oauth2_scheme)):
    """Obtiene todos los usuarios de la base de datos simulada, solo accesible para administradores"""
    # Decodificar el token y obtener el ID del usuario y su rol
    user_id_from_token,user_role = decode_access_token(token)
    current_user = fake_users_db.get(user_id_from_token)

    # Verificar que el usuario exista en la base de datos
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado"
        )

    # Verificar si el usuario tiene el rol de administrador
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para ver todos los usuarios"
        )

    # Retornar todos los usuarios si el usuario es administrador
    return list(fake_users_db.values())


# Endpoint para crear un nuevo usuario
@app.post("/users", response_model=UserInDB)
def create_user(user: UserCreate,token: str = Depends(oauth2_scheme)):
    """Crea un nuevo usuario en la base de datos simulada, solo accesible para administradores"""

    # Decodificar el token para obtener el user_id
    user_id,user_role = decode_access_token(token)

    # Obtener el usuario de la base de datos simulada
    current_user = get_user(fake_users_db, user_id,user_role)

    # Verificar si el usuario tiene el rol de administrador
    if current_user is None or current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para crear un nuevo usuario",
        )
    
    while True:
        new_id = randrange(1, 1000000)  # Genera un ID aleatorio entre 1 y 1,000,000
        if new_id not in fake_users_db:  # Asegúrate de que no se repita
            break

    # Hashear la contraseña del nuevo usuario
    hashed_password = get_password_hash(user.password)  # Hashea la contraseña
    fake_users_db[new_id] = {  # Agrega el nuevo usuario al diccionario
        "id": new_id,
        "username": user.username,
        "hashed_password": hashed_password,
        "disabled": False,
        "role":  user.role,
    }
    return fake_users_db[new_id]  # Retorna el usuario creado


@app.put("/users/{user_id}", response_model=UserInDB)
def update_user(
    user_id: int, 
    user_update: UserUpdate, 
    token: str = Depends(oauth2_scheme)
):
    # Decodificar el token para obtener user_id y role
    user_id_from_token, role_from_token = decode_access_token(token)
    print("User ID from token:", user_id_from_token)
    print("Role from token:", role_from_token)

    # Verificar que el user_id sea válido
    if not isinstance(user_id_from_token, int):
        raise HTTPException(status_code=400, detail="Token inválido. user_id debe ser un entero.")

    # Verificar el usuario autenticado
    current_user = fake_users_db.get(user_id_from_token)
    print("Current user:", current_user)

    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado"
        )
    
    # Validar permisos
    if role_from_token != "admin" and user_id_from_token != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para modificar este usuario"
        )

    # Buscar usuario por ID
    user = fake_users_db.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # Actualizar los datos
    if user_update.password:
        user["hashed_password"] = get_password_hash(user_update.password)
    if user_update.disabled is not None:
        user["disabled"] = user_update.disabled
    if user_update.username:
        user["username"] = user_update.username
    if user_update.role:
        user["role"] = user_update.role
    
    return user





@app.delete("/users/{user_id}")
def delete_user(
    user_id: int, 
    token: str = Depends(oauth2_scheme)  # Obtener el token del encabezado Authorization
):
    """Elimina un usuario de la base de datos, solo accesible para administradores o el propio usuario"""
    
    # Decodificar el token y obtener el ID del usuario y su rol
    user_id_from_token, role_from_token = decode_access_token(token)
    print("User ID from token:", user_id_from_token)
    print("Role from token:", role_from_token)

    # Verificar que el user_id sea válido
    if not isinstance(user_id_from_token, int):
        raise HTTPException(status_code=400, detail="Token inválido. user_id debe ser un entero.")
    
    current_user = fake_users_db.get(user_id_from_token)
    print("Current user:", current_user)

    # Verificar que el usuario autenticado esté en la base de datos
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado"
        )
    
    # Si el usuario no es administrador y está intentando eliminar otro usuario, denegar el acceso
    if role_from_token != "admin" and user_id_from_token != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes permiso para eliminar este usuario"
        )

    # Verificar que el usuario exista en la base de datos
    if user_id not in fake_users_db:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # Eliminar el usuario de la base de datos
    del fake_users_db[user_id]  
    return {"detail": "Usuario eliminado"}  # Confirmar que el usuario fue eliminado


