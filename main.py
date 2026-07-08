import jwt
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-owlcbe0r.apps.exam.local"

# DHYAN RAHE: In lines ke aage koi SPACE (khali jagah) nahi honi chahiye!
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuYcxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMIDEkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXcWyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfWed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfISI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIXdQIDAQAB-----END PUBLIC KEY-----"""

class TokenRequest(BaseModel):
    token: str

@app.post("/verify")
async def verify_token(request: TokenRequest):
    try:
        # Humne yahan leeway=60 (seconds) add kiya hai clock skew fix karne ke liye
        payload = jwt.decode(
            request.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            leeway=60 
        )
        
        return {
            "valid": True,
            "email": payload.get("email"),
            "sub": payload.get("sub"),
            "aud": payload.get("aud")
        }
        
    except Exception as e:
        # Agar token fail hota hai, toh exact reason ab Render ke logs mein print hoga
        print(f"TOKEN REJECTED BECAUSE: {type(e).__name__} - {str(e)}")
        return JSONResponse(status_code=401, content={"valid": False})
