from fastapi import FastAPI, HTTPException, Depends
from typing import List
from database import SessionLocal, engine
from model import User
from security import *


app = FastAPI()

# Dependency for getting database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Authentication dependency (unchanged)
def authenticate_user(db, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

# Signup endpoint
@app.post("/signup/", response_model=Token)
def signup(user: UserCreate, db = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    token = create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}


# Login endpoint (unchanged)
@app.post("/login/", response_model=Token)
def login(user: UserLogin, db = Depends(get_db)):
    db_user = authenticate_user(db, user.email, user.password)
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(data={"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

# Token authentication dependency (unchanged)
def get_current_user(token: str = Depends(decode_token)):
    if token is None:
        raise HTTPException(status_code=401, detail="Invalid or missing token")
    return token

# AddPost endpoint (unchanged)
@app.post("/addpost/", response_model=PostID)
def add_post(post: Post, token: str = Depends(get_current_user), db = Depends(get_db)):
    # Your implementation to save post in memory goes here
    # Here, we'll just return a dummy post_id
    return {"post_id": 123}

# GetPosts endpoint (unchanged)
@app.get("/getposts/", response_model=List[Post])
def get_posts(token: str = Depends(get_current_user)):
    # Your implementation to get user's posts goes here
    # Here, we'll just return a dummy list of posts
    return [{"text": "Post 1"}, {"text": "Post 2"}]

# DeletePost endpoint (unchanged)
@app.delete("/deletepost/")
def delete_post(post_id: int, token: str = Depends(get_current_user), db = Depends(get_db)):
    # Your implementation to delete post from memory goes here
    # Here, we'll just return a success message
    return {"message": "Post deleted successfully"}
