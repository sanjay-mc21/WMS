import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from django.contrib.auth.models import User
from api.models import UserProfile
from rest_framework.authtoken.models import Token

# Create demo users
def create_demo_user(username, email, password, user_type):
    # Check if user already exists
    if User.objects.filter(username=username).exists():
        print(f"User {username} already exists")
        user = User.objects.get(username=username)
    else:
        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        print(f"Created user: {username}")
        
        # Create user profile
        UserProfile.objects.create(
            user=user,
            user_type=user_type
        )
        print(f"Created profile with type: {user_type}")
    
    # Create or get token
    token, _ = Token.objects.get_or_create(user=user)
    print(f"Token: {token.key}")
    
    return user

# Create demo accounts for each role
print("Creating demo accounts...")

# 1. Super Admin
super_admin = create_demo_user(
    username="superadmin",
    email="superadmin@example.com",
    password="password123",
    user_type="super_admin"
)

# 2. Admin
admin = create_demo_user(
    username="admin",
    email="admin@example.com",
    password="password123",
    user_type="admin"
)

# 3. Client
client = create_demo_user(
    username="client",
    email="client@example.com",
    password="password123",
    user_type="client"
)

print("\nDemo Accounts Created:")
print("----------------------")
print("Super Admin:")
print(f"  Username: superadmin")
print(f"  Password: password123")
print(f"  Role: Super Admin")
print("\nAdmin:")
print(f"  Username: admin")
print(f"  Password: password123")
print(f"  Role: Admin")
print("\nClient:")
print(f"  Username: client")
print(f"  Password: password123")
print(f"  Role: Client") 