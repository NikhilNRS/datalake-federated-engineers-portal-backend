from pydantic import BaseModel


class PKCESecret(BaseModel):
    code_verifier: str
    code_verifier_hash: bytes
    code_challenge: str
