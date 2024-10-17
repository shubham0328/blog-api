from fastapi import FastAPI, HTTPException, Depends, status, Form
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List, Dict, Optional, Set
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta

app = FastAPI()

# Secret key for JWT
SECRET_KEY = "your_secret_key"  # Replace with a more secure key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Sample data storage
blogs = {}
comments = {}
likes = {}
users = {}
categories = {}  # New dictionary for categories
tags = {}        # New dictionary for tags

# User models
class User(BaseModel):
    username: str
    full_name: Optional[str] = None
    email: str

class UserInDB(User):
    hashed_password: str

# Blog models
class Blog(BaseModel):
    title: str
    content: str
    category: str
    tags: str  # Using string for tags

class BlogResponse(Blog):
    id: int
    likes: int = 0
    dislikes: int = 0

# Comment models
class Comment(BaseModel):
    content: str

class CommentResponse(Comment):
    id: int
    blog_id: int
    username: str

# Tag and Category models
class Tag(BaseModel):
    name: str

class Category(BaseModel):
    name: str

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str):
    user = users.get(username)
    if user and verify_password(password, user.hashed_password):
        return user
    return None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = users.get(username)
    if user is None:
        raise credentials_exception
    return user

# Custom login dependency
def login_form(username: str = Form(), password: str = Form()):
    return {"username": username, "password": password}

# User registration
@app.post("/register/", response_model=User)
def register_user(user: User, password: str):
    if user.username in users:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = get_password_hash(password)
    users[user.username] = UserInDB(**user.dict(), hashed_password=hashed_password)
    return user

# Token endpoint for login
@app.post("/token", response_model=dict)
def login(data: dict = Depends(login_form)):
    username, password = data["username"], data["password"]
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Protected CRUD endpoints for blogs
@app.post("/blogs/", response_model=BlogResponse)
async def create_blog(blog: Blog, current_user: User = Depends(get_current_user)):
    if blog.category not in categories:
        raise HTTPException(status_code=400, detail="Category does not exist")
    blog_id = len(blogs) + 1
    blogs[blog_id] = blog
    likes[blog_id] = {"likes": set(), "dislikes": set()}
    return BlogResponse(id=blog_id, **blog.dict(), likes=0, dislikes=0)


#pagination for fetching posts
@app.get("/blogs/", response_model=List[BlogResponse])
async def get_blogs(skip: int = 0, limit: int = 10, current_user: User = Depends(get_current_user)):
    blog_items = list(blogs.items())[skip: skip + limit]
    response = [
        BlogResponse(
            id=blog_id,
            likes=len(likes_data["likes"]),
            dislikes=len(likes_data["dislikes"]),
            **blog.dict()
        ) for blog_id, blog in blog_items
        for likes_data in [likes.get(blog_id, {"likes": set(), "dislikes": set()})]
    ]
    return response

@app.get("/blogs/{blog_id}", response_model=BlogResponse)
async def get_blog(blog_id: int, current_user: User = Depends(get_current_user)):
    blog = blogs.get(blog_id)
    if not blog:
        raise HTTPException(status_code=404, detail="Blog not found")
    likes_data = likes.get(blog_id, {"likes": set(), "dislikes": set()})
    return BlogResponse(
        id=blog_id,
        likes=len(likes_data["likes"]),
        dislikes=len(likes_data["dislikes"]),
        **blog.dict()
    )

@app.put("/blogs/{blog_id}", response_model=BlogResponse)
async def update_blog(blog_id: int, blog: Blog, current_user: User = Depends(get_current_user)):
    if blog_id not in blogs:
        raise HTTPException(status_code=404, detail="Blog not found")
    if blog.category not in categories:
        raise HTTPException(status_code=400, detail="Category does not exist")
    blogs[blog_id] = blog
    return BlogResponse(id=blog_id, **blog.dict())

@app.delete("/blogs/{blog_id}", response_model=dict)
async def delete_blog(blog_id: int, current_user: User = Depends(get_current_user)):
    if blog_id not in blogs:
        raise HTTPException(status_code=404, detail="Blog not found")
    del blogs[blog_id]
    likes.pop(blog_id, None)
    return {"message": "Blog deleted successfully"}

# New endpoints for like and dislike
@app.post("/blogs/{blog_id}/like", response_model=dict)
async def like_blog(blog_id: int, current_user: User = Depends(get_current_user)):
    if blog_id not in blogs:
        raise HTTPException(status_code=404, detail="Blog not found")
    user = current_user.username
    likes_data = likes.setdefault(blog_id, {"likes": set(), "dislikes": set()})
    if user in likes_data["dislikes"]:
        likes_data["dislikes"].remove(user)
    likes_data["likes"].add(user)
    return {"message": "Blog liked", "likes": len(likes_data["likes"]), "dislikes": len(likes_data["dislikes"])}

@app.post("/blogs/{blog_id}/dislike", response_model=dict)
async def dislike_blog(blog_id: int, current_user: User = Depends(get_current_user)):
    if blog_id not in blogs:
        raise HTTPException(status_code=404, detail="Blog not found")
    user = current_user.username
    likes_data = likes.setdefault(blog_id, {"likes": set(), "dislikes": set()})
    if user in likes_data["likes"]:
        likes_data["likes"].remove(user)
    likes_data["dislikes"].add(user)
    return {"message": "Blog disliked", "likes": len(likes_data["likes"]), "dislikes": len(likes_data["dislikes"])}

# New endpoints for tags with authentication
@app.post("/tags/", response_model=Tag)
async def create_tag(tag: Tag, current_user: User = Depends(get_current_user)):
    if tag.name in tags:
        raise HTTPException(status_code=400, detail="Tag already exists")
    tags[tag.name] = tag.name
    return tag

@app.get("/tags/", response_model=List[Tag])
async def get_tags(current_user: User = Depends(get_current_user)):
    return [Tag(name=tag) for tag in tags.keys()]

@app.delete("/tags/{tag_name}", response_model=dict)
async def delete_tag(tag_name: str, current_user: User = Depends(get_current_user)):
    if tag_name not in tags:
        raise HTTPException(status_code=404, detail="Tag not found")
    del tags[tag_name]
    return {"message": "Tag deleted successfully"}

# New endpoints for categories with authentication
@app.post("/categories/", response_model=Category)
async def create_category(category: Category, current_user: User = Depends(get_current_user)):
    if category.name in categories:
        raise HTTPException(status_code=400, detail="Category already exists")
    categories[category.name] = category.name
    return category

@app.get("/categories/", response_model=List[Category])
async def get_categories(current_user: User = Depends(get_current_user)):
    return [Category(name=category) for category in categories.keys()]

@app.delete("/categories/{category_name}", response_model=dict)
async def delete_category(category_name: str, current_user: User = Depends(get_current_user)):
    if category_name not in categories:
        raise HTTPException(status_code=404, detail="Category not found")
    del categories[category_name]
    return {"message": "Category deleted successfully"}

# New Comment endpoints with authentication
@app.post("/blogs/{blog_id}/comments/", response_model=CommentResponse)
async def create_comment(blog_id: int, comment: Comment, current_user: User = Depends(get_current_user)):
    if blog_id not in blogs:
        raise HTTPException(status_code=404, detail="Blog not found")
    comment_id = len(comments) + 1
    comment_data = CommentResponse(id=comment_id, blog_id=blog_id, username=current_user.username, content=comment.content)
    comments[comment_id] = comment_data
    return comment_data

@app.get("/blogs/{blog_id}/comments/", response_model=List[CommentResponse])
async def get_comments(blog_id: int, current_user: User = Depends(get_current_user)):
    if blog_id not in blogs:
        raise HTTPException(status_code=404, detail="Blog not found")
    return [comment for comment in comments.values() if comment.blog_id == blog_id]

@app.delete("/blogs/{blog_id}/comments/{comment_id}", response_model=dict)
async def delete_comment(blog_id: int, comment_id: int, current_user: User = Depends(get_current_user)):
    if blog_id not in blogs or comment_id not in comments or comments[comment_id].blog_id != blog_id:
        raise HTTPException(status_code=404, detail="Comment not found")
    if comments[comment_id].username != current_user.username:
        raise HTTPException(status_code=403, detail="Not authorized to delete this comment")
    del comments[comment_id]
    return {"message": "Comment deleted successfully"}

# Run the application
# uvicorn blog_api:app --reload
