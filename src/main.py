import fastapi
import logging

app = fastapi.FastAPI()
logging.basicConfig(level=logging.INFO)


#=======================================================================================================================
# SECURITY
#=======================================================================================================================
def create_none_authentication_handler():
   return lambda: "anonymous"

def create_basic_authentication_handler():
    basic_security = fastapi.security.HTTPBasic()

    def authenticate_basic(credentials: fastapi.security.HTTPBasicCredentials = fastapi.Depends(basic_security)):
        correct_username = credentials.username == "test_user"
        correct_password = credentials.password == "pass123"
        if not (correct_username and correct_password):
            raise InvalidBasicCredentials
        return credentials.username

    return authenticate_basic

def create_oauth2_token_authentication_handler():
    # available flows: OAuth2PasswordBearer and OAuth2AuthorizationCodeBearer
    oauth2_scheme = fastapi.security.OAuth2PasswordBearer(tokenUrl="token")

    def authenticate_token(token: str = fastapi.Depends(oauth2_scheme)):
        correct_token = token == "my_token"
        if not correct_token:
            raise InvalidToken
        return "test_user"

    return authenticate_token

def create_authentication_handler(security_type: str):
    if security_type == "none":
        logging.info("none authentication handler created")
        return create_none_authentication_handler()
    elif security_type == "basic":
        logging.info("basic authentication handler created")
        return create_basic_authentication_handler()
    elif security_type == "token":
        logging.info("token based authentication handler created")
        return create_oauth2_token_authentication_handler()
    else:
        raise RuntimeError("Not supported authentication type " + security_type)


#=======================================================================================================================
# APIs
#=======================================================================================================================
authentication_handler = create_authentication_handler("token")

@app.get("/hello")
def hello(name: str = None):
    message = "Hello " + name if name is not None else "Hello world"
    return {"message": message}

@app.get("/hello/me")
def hello_me(username: str = fastapi.Depends(authentication_handler)):
    return {"message": "Hello " + username}

@app.get("/unknown")
def unknown_method():
    raise NotAllowedMethod


#=======================================================================================================================
# EXCEPTIONS
#=======================================================================================================================
class NotAllowedMethod(fastapi.HTTPException):
    def __init__(self):
        super().__init__(
            status_code=405,
            detail="Not allowed method"
        )

class InvalidBasicCredentials(fastapi.HTTPException):
    def __init__(self):
        super().__init__(
            status_code=401,
            detail="Invalid credentials"
        )

class InvalidToken(fastapi.HTTPException):
    def __init__(self):
        super().__init__(
            status_code=401,
            detail="Invalid token"
        )

