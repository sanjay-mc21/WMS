import os
import django
import sys

# Set up Django environment
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from api.models import UserProfile

User = get_user_model()

def create_dummy_accounts():
    # Create dummy admin accounts
    admin_accounts = [
        {
            'username': 'admin1',
            'email': 'admin1@example.com',
            'password': 'admin123',
            'user_type': 'admin',
            'first_name': 'John',
            'last_name': 'Doe',
        },
        {
            'username': 'admin2',
            'email': 'admin2@example.com',
            'password': 'admin123',
            'user_type': 'admin',
            'first_name': 'Jane',
            'last_name': 'Smith',
        },
        {
            'username': 'admin3',
            'email': 'admin3@example.com',
            'password': 'admin123',
            'user_type': 'admin',
            'first_name': 'Michael',
            'last_name': 'Johnson',
        },
    ]

    # Create dummy client accounts
    client_accounts = [
        {
            'username': 'client1',
            'email': 'client1@example.com',
            'password': 'client123',
            'user_type': 'client',
            'first_name': 'Alice',
            'last_name': 'Brown',
        },
        {
            'username': 'client2',
            'email': 'client2@example.com',
            'password': 'client123',
            'user_type': 'client',
            'first_name': 'Bob',
            'last_name': 'Wilson',
        },
        {
            'username': 'client3',
            'email': 'client3@example.com',
            'password': 'client123',
            'user_type': 'client',
            'first_name': 'Carol',
            'last_name': 'Davis',
        },
    ]

    # Create admin accounts
    for admin in admin_accounts:
        if not User.objects.filter(username=admin['username']).exists():
            user = User.objects.create(
                username=admin['username'],
                email=admin['email'],
                password=make_password(admin['password']),
                first_name=admin['first_name'],
                last_name=admin['last_name'],
            )
            UserProfile.objects.create(
                user=user,
                user_type=admin['user_type'],
            )
            print(f"Created admin account: {admin['username']}")

    # Create client accounts
    for client in client_accounts:
        if not User.objects.filter(username=client['username']).exists():
            user = User.objects.create(
                username=client['username'],
                email=client['email'],
                password=make_password(client['password']),
                first_name=client['first_name'],
                last_name=client['last_name'],
            )
            UserProfile.objects.create(
                user=user,
                user_type=client['user_type'],
            )
            print(f"Created client account: {client['username']}")

if __name__ == '__main__':
    create_dummy_accounts() 