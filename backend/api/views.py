from django.shortcuts import render
from rest_framework import viewsets, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import action
from django.contrib.auth.models import User
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from .models import Task, UserProfile, Report
from .serializers import TaskSerializer, UserSerializer, UserProfileSerializer, ReportSerializer
from django.contrib.auth import authenticate, login, logout
from django.db.models import Count, Case, When, IntegerField, Value
from django.db.models.functions import Coalesce
from django.utils import timezone
from datetime import timedelta
import csv
import io
import json
from django.db import transaction
from django.http import Http404
import traceback
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie
from django.utils.decorators import method_decorator

# Authentication views
@method_decorator(csrf_exempt, name='dispatch')
class CustomAuthToken(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        user_profile = UserProfile.objects.get(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email,
            'username': user.username,
            'user_type': user_profile.user_type
        })

# Registration view
@method_decorator(csrf_exempt, name='dispatch')
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user_id': user.pk,
                'email': user.email,
                'username': user.username,
                'user_type': user.profile.user_type
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# CSRF Token endpoint
@method_decorator(ensure_csrf_cookie, name='dispatch')
class GetCSRFToken(APIView):
    permission_classes = []
    
    def get(self, request):
        return Response({'detail': 'CSRF cookie set'})

# User views
class UserViewSet(viewsets.ViewSet):
    """
    A viewset for viewing and editing user instances.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def list(self, request):
        """
        Get a list of all users (admin only)
        """
        # Check if user is admin
        try:
            profile = UserProfile.objects.get(user=request.user)
            if profile.user_type != 'admin':
                return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data)
    
    def retrieve(self, request, pk=None):
        """
        Get a specific user
        """
        try:
            user = User.objects.get(pk=pk)
            serializer = UserSerializer(user)
            return Response(serializer.data)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    
    @method_decorator(csrf_exempt, name='dispatch')
    @action(detail=False, methods=['get'])
    def me(self, request):
        """
        Get the current user's profile
        """
        user = request.user
        data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'full_name': f"{user.first_name} {user.last_name}",
            'first_name': user.first_name,
            'last_name': user.last_name,
            'phone': getattr(user, 'phone', None),
            'role': getattr(user, 'role', 'user'),
            'date_joined': user.date_joined.strftime('%Y-%m-%d'),
            'is_staff': user.is_staff,
            'is_active': user.is_active,
        }
        return Response(data)

    @method_decorator(csrf_exempt, name='dispatch')
    @action(detail=False, methods=['post'])
    def login(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        
        if user:
            login(request, user)
            profile = UserProfile.objects.get(user=user)
            return Response({
                'user': UserSerializer(user).data,
                'user_type': profile.user_type
            })
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

    @method_decorator(csrf_exempt, name='dispatch')
    @action(detail=False, methods=['post'])
    def logout(self, request):
        logout(request)
        return Response({'message': 'Logged out successfully'})

# Client views
class ClientViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]
    
    def list(self, request):
        try:
            # Check if user is admin
            try:
                profile = UserProfile.objects.get(user=request.user)
                if profile.user_type != 'admin':
                    return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
            except UserProfile.DoesNotExist:
                return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)
            
            # Get all client users with their task statistics
            clients = User.objects.filter(profile__user_type='client')
            
            # Prepare client data with task statistics
            client_data = []
            for client in clients:
                try:
                    client_tasks = Task.objects.filter(assigned_to=client)
                    total_tasks = client_tasks.count()
                    pending_tasks = client_tasks.filter(status__in=['pending', 'in_progress']).count()
                    completed_tasks = client_tasks.filter(status='completed').count()
                    
                    client_data.append({
                        'id': client.id,
                        'username': client.username,
                        'email': client.email,
                        'first_name': client.first_name,
                        'last_name': client.last_name,
                        'date_joined': client.date_joined,
                        'phone': getattr(client, 'phone', ''),
                        'address': getattr(client, 'address', ''),
                        'company': getattr(client, 'company', ''),
                        'statistics': {
                            'total_tasks': total_tasks,
                            'pending_tasks': pending_tasks,
                            'completed_tasks': completed_tasks,
                        },
                        'task_count': total_tasks,
                        'assigned_tasks': TaskSerializer(
                            client_tasks.order_by('-created_at')[:5],
                            many=True
                        ).data
                    })
                except Exception as e:
                    # If we have an error with a specific client, log it but continue
                    print(f"Error processing client {client.username}: {str(e)}")
                    continue
            
            return Response(client_data)
        except Exception as e:
            # Log the error and return a friendly response
            print(f"Error in client list view: {str(e)}")
            return Response(
                {'error': True, 'message': 'Internal server error while fetching clients'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# Task views
class TaskViewSet(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        profile = UserProfile.objects.get(user=self.request.user)
        
        # Use select_related to optimize queries
        queryset = Task.objects.select_related('service_engineer', 'assigned_to').prefetch_related('reports')
        
        # Process status filter for all user types
        status_param = self.request.query_params.get('status', None)
        
        if status_param:
            # Allow filtering by multiple statuses
            statuses = status_param.split(',')
            queryset = queryset.filter(status__in=statuses)
        
        if profile.user_type == 'admin':
            # Add filtering options for admin
            cluster = self.request.query_params.get('cluster', None)
            service_type = self.request.query_params.get('service_type', None)
            assigned_to = self.request.query_params.get('assigned_to', None)
            
            if cluster:
                queryset = queryset.filter(cluster=cluster)
            if service_type:
                queryset = queryset.filter(service_type=service_type)
            if assigned_to:
                queryset = queryset.filter(assigned_to_id=assigned_to)
                
            return queryset
        elif profile.user_type == 'client':
            # For clients, show approved tasks as well
            if not status_param:
                return queryset.filter(
                    assigned_to=self.request.user
                ).order_by('-updated_at')
            return queryset.filter(assigned_to=self.request.user).order_by('-updated_at')
        
        # For service engineers
        return queryset.filter(service_engineer=self.request.user).order_by('-updated_at')

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        data = serializer.data

        # Process each task to add engineer and client names
        for task in data:
            # Handle service engineer
            if task.get('service_engineer'):
                if isinstance(task['service_engineer'], dict):
                    task['service_engineer_name'] = task['service_engineer'].get('username', 'Unassigned')
                else:
                    task['service_engineer_name'] = 'Unassigned'

            # Handle assigned_to (client)
            if task.get('assigned_to'):
                if isinstance(task['assigned_to'], dict):
                    client = task['assigned_to']
                    first_name = client.get('first_name', '')
                    last_name = client.get('last_name', '')
                    full_name = f"{first_name} {last_name}".strip()
                    task['client_name'] = full_name if full_name else client.get('username', 'Unknown Client')
                else:
                    task['client_name'] = 'Unknown Client'

        return Response(data)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Handle assigned_to_id properly if it's in the request data
        if 'assigned_to_id' in request.data and request.data['assigned_to_id']:
            try:
                client = User.objects.get(id=request.data['assigned_to_id'])
                request.data._mutable = True
                request.data['assigned_to'] = client.id
                if not 'service_engineer' in request.data or not request.data['service_engineer']:
                    request.data['service_engineer'] = client.id
                request.data._mutable = False
            except User.DoesNotExist:
                pass
        # Set service_engineer to be the same as assigned_to (client)
        elif 'assigned_to' in request.data and (not 'service_engineer' in request.data or not request.data['service_engineer']):
            request.data._mutable = True
            request.data['service_engineer'] = request.data['assigned_to']
            request.data._mutable = False
        
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def perform_create(self, serializer):
        serializer.save()

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        """Get task statistics"""
        profile = UserProfile.objects.get(user=request.user)
        if profile.user_type != 'admin':
            return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)

        queryset = self.get_queryset()
        
        # Get basic statistics
        total_tasks = queryset.count()
        pending_tasks = queryset.filter(status='pending').count()
        completed_tasks = queryset.filter(status='completed').count()
        in_progress_tasks = queryset.filter(status='in_progress').count()

        # Get tasks by status
        tasks_by_status = queryset.values('status').annotate(count=Count('id'))
        
        # Get tasks by cluster
        tasks_by_cluster = queryset.values('cluster').annotate(count=Count('id'))
        
        # Get tasks by service type
        tasks_by_service_type = queryset.values('service_type').annotate(count=Count('id'))
        
        # Get tasks by service engineer
        tasks_by_engineer = queryset.values(
            'service_engineer__username',
            'service_engineer__first_name',
            'service_engineer__last_name'
        ).annotate(count=Count('id'))

        return Response({
            'total_tasks': total_tasks,
            'pending_tasks': pending_tasks,
            'completed_tasks': completed_tasks,
            'in_progress_tasks': in_progress_tasks,
            'tasks_by_status': tasks_by_status,
            'tasks_by_cluster': tasks_by_cluster,
            'tasks_by_service_type': tasks_by_service_type,
            'tasks_by_engineer': tasks_by_engineer,
        })

    @action(detail=False, methods=['post'], url_path='upload')
    def upload_tasks(self, request):
        """
        Upload tasks from a CSV or JSON file.
        CSV format: title,description,client_id,due_date,priority,is_urgent,status,...
        JSON format: [{"title": "Task 1", "description": "...", ...}, ...]
        """
        # Check if user is admin
        try:
            profile = UserProfile.objects.get(user=request.user)
            if profile.user_type != 'admin':
                return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Get the uploaded file
        file_obj = request.FILES.get('file')
        if not file_obj:
            return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Process based on file type
        filename = file_obj.name.lower()
        
        try:
            with transaction.atomic():
                if filename.endswith('.csv'):
                    results = self._process_csv_file(file_obj, request.user)
                elif filename.endswith('.json'):
                    results = self._process_json_file(file_obj, request.user)
                else:
                    return Response(
                        {'error': 'Unsupported file format. Use CSV or JSON.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                return Response({
                    'message': 'File processed successfully',
                    'created': results['created'],
                    'updated': results['updated'],
                    'errors': results['errors']
                }, status=status.HTTP_200_OK)
                
        except Exception as e:
            return Response(
                {'error': f'Error processing file: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _process_csv_file(self, file_obj, user):
        """Process a CSV file and create/update tasks"""
        content = file_obj.read().decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(content))
        
        results = {'created': 0, 'updated': 0, 'errors': []}
        
        for row in csv_reader:
            # Look for task ID for updates
            task_id = row.get('id', None)
            
            # Clean data
            data = self._clean_task_data(row)
            
            try:
                if task_id:
                    # Try to update existing task
                    try:
                        task = Task.objects.get(id=task_id)
                        serializer = TaskSerializer(task, data=data, partial=True)
                        if serializer.is_valid():
                            serializer.save()
                            results['updated'] += 1
                        else:
                            results['errors'].append({
                                'row': dict(row),
                                'errors': serializer.errors
                            })
                    except Task.DoesNotExist:
                        # Task with ID not found, create new
                        serializer = TaskSerializer(data=data)
                        if serializer.is_valid():
                            serializer.save(created_by=user)
                            results['created'] += 1
                        else:
                            results['errors'].append({
                                'row': dict(row),
                                'errors': serializer.errors
                            })
                else:
                    # Create new task
                    serializer = TaskSerializer(data=data)
                    if serializer.is_valid():
                        serializer.save(created_by=user)
                        results['created'] += 1
                    else:
                        results['errors'].append({
                            'row': dict(row),
                            'errors': serializer.errors
                        })
            except Exception as e:
                results['errors'].append({
                    'row': dict(row),
                    'errors': str(e)
                })
        
        return results
    
    def _process_json_file(self, file_obj, user):
        """Process a JSON file and create/update tasks"""
        content = json.loads(file_obj.read().decode('utf-8'))
        
        if not isinstance(content, list):
            raise ValueError("JSON file must contain an array of tasks")
        
        results = {'created': 0, 'updated': 0, 'errors': []}
        
        for task_data in content:
            # Look for task ID for updates
            task_id = task_data.get('id', None)
            
            # Clean data
            data = self._clean_task_data(task_data)
            
            try:
                if task_id:
                    # Try to update existing task
                    try:
                        task = Task.objects.get(id=task_id)
                        serializer = TaskSerializer(task, data=data, partial=True)
                        if serializer.is_valid():
                            serializer.save()
                            results['updated'] += 1
                        else:
                            results['errors'].append({
                                'task': task_data,
                                'errors': serializer.errors
                            })
                    except Task.DoesNotExist:
                        # Task with ID not found, create new
                        serializer = TaskSerializer(data=data)
                        if serializer.is_valid():
                            serializer.save(created_by=user)
                            results['created'] += 1
                        else:
                            results['errors'].append({
                                'task': task_data,
                                'errors': serializer.errors
                            })
                else:
                    # Create new task
                    serializer = TaskSerializer(data=data)
                    if serializer.is_valid():
                        serializer.save(created_by=user)
                        results['created'] += 1
                    else:
                        results['errors'].append({
                            'task': task_data,
                            'errors': serializer.errors
                        })
            except Exception as e:
                results['errors'].append({
                    'task': task_data,
                    'errors': str(e)
                })
        
        return results
    
    def _clean_task_data(self, data):
        """Clean and convert task data to appropriate types"""
        clean_data = {}
        
        # Copy fields that don't need conversion
        for field in ['title', 'description', 'status', 'priority', 'category']:
            if field in data and data[field]:
                clean_data[field] = data[field]
        
        # Handle client_id/assigned_to conversion
        if 'client_id' in data and data['client_id']:
            try:
                client = User.objects.get(id=data['client_id'])
                clean_data['assigned_to'] = client.id
                # Also set service_engineer to the same client
                clean_data['service_engineer'] = client.id
            except User.DoesNotExist:
                pass
        
        # Handle direct assigned_to field
        if 'assigned_to' in data and data['assigned_to']:
            clean_data['assigned_to'] = data['assigned_to']
            # Also set service_engineer to be the same as assigned_to (client)
            if 'service_engineer' not in data or not data['service_engineer']:
                clean_data['service_engineer'] = data['assigned_to']
            
        # Handle service_engineer field only if explicitly provided
        if 'service_engineer' in data and data['service_engineer']:
            clean_data['service_engineer'] = data['service_engineer']
            
        # Handle service_engineer_id field only if explicitly provided
        if 'service_engineer_id' in data and data['service_engineer_id']:
            try:
                engineer = User.objects.get(id=data['service_engineer_id'])
                clean_data['service_engineer'] = engineer.id
            except User.DoesNotExist:
                pass
        
        # Handle boolean fields
        if 'is_urgent' in data:
            if isinstance(data['is_urgent'], str):
                clean_data['is_urgent'] = data['is_urgent'].lower() in ['true', 'yes', '1']
            else:
                clean_data['is_urgent'] = bool(data['is_urgent'])
        
        # Handle date fields
        if 'due_date' in data and data['due_date']:
            clean_data['due_date'] = data['due_date']
        
        return clean_data

    @action(detail=False, methods=['get'])
    def client_tasks(self, request):
        """Get tasks for the current client"""
        try:
            profile = UserProfile.objects.get(user=request.user)
            if profile.user_type != 'client':
                return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)

        # Get client's tasks
        client_tasks = Task.objects.filter(assigned_to=request.user)
        
        # Apply filters if provided
        status = request.query_params.get('status', None)
        if status:
            client_tasks = client_tasks.filter(status=status)

        # Serialize tasks
        serializer = self.get_serializer(client_tasks, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['post'], url_path='submit-report')
    def submit_report(self, request):
        """Submit a new report"""
        try:
            data = request.data.copy()
            
            # Extract nested structured data if it exists in 'content'
            content_data = data.get('content', None)
            if content_data and isinstance(content_data, dict):
                # Basic description for backward compatibility
                data['content'] = content_data.get('description', '') 
                
                # Extract structured data sections
                if 'details' in content_data:
                    details = content_data['details']
                    if 'Task Details' in details:
                        data['task_details'] = details['Task Details']
                    if 'Engine Details' in details:
                        data['engine_details'] = details['Engine Details']
                    if 'Alternator Details' in details:
                        data['alternator_details'] = details['Alternator Details']
                    if 'DG Check Points' in details:
                        data['dg_checkpoints'] = details['DG Check Points']
                    if 'Alternator Check Points' in details:
                        data['alternator_checkpoints'] = details['Alternator Check Points']
                    if 'Engine Check Points' in details:
                        data['engine_checkpoints'] = details['Engine Check Points']
                    if 'General Check Points' in details:
                        data['general_checkpoints'] = details['General Check Points']
                
                # Extract conclusion if it exists
                if 'conclusion' in content_data:
                    data['conclusion'] = content_data['conclusion']
            
            # Create serializer with the processed data
            serializer = ReportSerializer(data=data)
            
            # Validate the data
            if serializer.is_valid():
                # Save the report with the current user as the submitter
                report = serializer.save(submitted_by=request.user)
                
                # If a task id is provided, link the report to that task and update its status
                task_id = data.get('task_id') or data.get('task')
                if task_id:
                    try:
                        print(f"Linking report to task with ID: {task_id}")
                        task = Task.objects.get(id=task_id)
                        report.task = task
                        
                        # Update task status to pending (waiting for approval)
                        task.status = 'pending'
                        task.save()
                        
                        report.save()
                        print(f"Report linked to task successfully, task status: {task.status}")
                    except Task.DoesNotExist:
                        print(f"Task with ID {task_id} not found")
                        pass  # Continue even if task doesn't exist
                    except Exception as e:
                        print(f"Error linking report to task: {str(e)}")
                        pass  # Continue even if there's an error
                
                # Return success response
                return Response({
                    'success': True,
                    'message': 'Report submitted successfully',
                    'id': report.id,
                    'title': report.title,
                    'status': report.status,
                }, status=status.HTTP_201_CREATED)
            else:
                # Return validation errors
                return Response({
                    'error': True,
                    'message': 'Validation error',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # Log the error
            print(f"Error submitting report: {str(e)}")
            
            # Return error response
            return Response({
                'error': True,
                'message': f'Failed to submit report: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'], url_path='reports')
    def task_reports(self, request):
        """Submit a task-specific report"""
        try:
            # Create serializer with request data
            serializer = ReportSerializer(data=request.data)
            
            # Validate the data
            if serializer.is_valid():
                # Save the report with the current user as the submitter
                report = serializer.save(submitted_by=request.user)
                
                # If a task id is provided, link the report to that task
                task_id = request.data.get('task_id') or request.data.get('task')
                if task_id:
                    try:
                        print(f"Linking report to task with ID: {task_id}")
                        task = Task.objects.get(id=task_id)
                        report.task = task
                        
                        # Update task status to pending (waiting for approval)
                        task.status = 'pending'
                        task.save()
                        
                        report.save()
                        print(f"Report linked to task successfully, task status: {task.status}")
                    except Task.DoesNotExist:
                        print(f"Task with ID {task_id} not found")
                        pass  # Continue even if task doesn't exist
                    except Exception as e:
                        print(f"Error linking report to task: {str(e)}")
                        pass  # Continue even if there's an error
                
                # Return success response
                return Response({
                    'success': True,
                    'message': 'Task report submitted successfully',
                    'id': report.id,
                    'title': report.title,
                    'status': report.status,
                }, status=status.HTTP_201_CREATED)
            else:
                # Return validation errors
                return Response({
                    'error': True,
                    'message': 'Validation error',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            # Log the error
            print(f"Error submitting task report: {str(e)}")
            
            # Return error response
            return Response({
                'error': True,
                'message': f'Failed to submit task report: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['get'], url_path='check-new-tasks')
    def check_new_tasks(self, request):
        """
        Lightweight endpoint for clients to check if there are new tasks
        """
        try:
            profile = UserProfile.objects.get(user=request.user)
            if profile.user_type != 'client':
                return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Get the last synced timestamp from request
        last_synced = request.query_params.get('last_synced', None)
        
        # If no timestamp provided, return all assigned tasks
        if not last_synced:
            tasks = Task.objects.filter(assigned_to=request.user).order_by('-updated_at')
            return Response({
                'new_tasks_available': tasks.exists(),
                'task_count': tasks.count(),
                'last_synced': timezone.now().isoformat()
            })
        
        try:
            last_synced_time = timezone.datetime.fromisoformat(last_synced)
            # Check for new or updated tasks since last sync
            new_tasks = Task.objects.filter(
                assigned_to=request.user,
                updated_at__gt=last_synced_time
            )
            
            return Response({
                'new_tasks_available': new_tasks.exists(),
                'task_count': new_tasks.count(),
                'last_synced': timezone.now().isoformat()
            })
            
        except ValueError:
            return Response({
                'error': 'Invalid timestamp format. Use ISO format (YYYY-MM-DDTHH:MM:SS.mmmmmm).'
            }, status=status.HTTP_400_BAD_REQUEST)

class AdminDashboardViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        # Check if user is admin
        try:
            profile = UserProfile.objects.get(user=request.user)
            if profile.user_type != 'admin':
                return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)

        # Get statistics
        total_clients = UserProfile.objects.filter(user_type='client').count()
        total_tasks = Task.objects.count()
        pending_tasks = Task.objects.filter(status='pending').count()
        completed_tasks = Task.objects.filter(status='completed').count()
        in_progress_tasks = Task.objects.filter(status='in_progress').count()

        # Get recent clients (last 7 days)
        recent_clients = User.objects.filter(
            profile__user_type='client',
            date_joined__gte=timezone.now() - timedelta(days=7)
        ).order_by('-date_joined')[:5]

        # Get recent tasks with more details
        recent_tasks = Task.objects.select_related('service_engineer', 'assigned_to').order_by('-created_at')[:5]

        # Get tasks by status with more details
        tasks_by_status = Task.objects.values('status').annotate(
            count=Count('id'),
            total=Count('id')
        )

        # Format tasks by status for the frontend
        formatted_tasks_by_status = [
            {
                'status': item['status'],
                'count': item['count'],
                'percentage': (item['count'] / total_tasks * 100) if total_tasks > 0 else 0
            }
            for item in tasks_by_status
        ]

        # Get tasks by cluster
        tasks_by_cluster = Task.objects.values('cluster').annotate(
            count=Count('id')
        )

        # Get tasks by service type
        tasks_by_service_type = Task.objects.values('service_type').annotate(
            count=Count('id')
        )

        return Response({
            'statistics': {
                'total_clients': total_clients,
                'total_tasks': total_tasks,
                'pending_tasks': pending_tasks,
                'completed_tasks': completed_tasks,
                'in_progress_tasks': in_progress_tasks,
            },
            'recent_clients': UserSerializer(recent_clients, many=True).data,
            'recent_tasks': TaskSerializer(recent_tasks, many=True).data,
            'tasks_by_status': formatted_tasks_by_status,
            'tasks_by_cluster': tasks_by_cluster,
            'tasks_by_service_type': tasks_by_service_type,
            'user': {
                'id': request.user.id,
                'username': request.user.username,
                'email': request.user.email,
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,
            }
        })

class ClientDashboardViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        # Check if user is client
        try:
            profile = UserProfile.objects.get(user=request.user)
            if profile.user_type != 'client':
                return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            # Initialize variables to prevent UnboundLocalError
            client_tasks = Task.objects.filter(assigned_to=request.user)
            task_stats = {}
            recent_tasks_data = []
            tasks_by_status = []

            # Check for ultra-minimal mode (absolutely fastest possible response)
            if request.query_params.get('minimal', 'false').lower() == 'true':
                # Just return the bare minimum stats - single DB query
                
                # Get statistics with a single optimized query
                task_stats = client_tasks.aggregate(
                    total_tasks=Coalesce(Count('id'), Value(0)),
                    pending_tasks=Coalesce(Count(Case(When(status='pending', then=1), output_field=IntegerField())), Value(0)),
                    in_progress_tasks=Coalesce(Count(Case(When(status='in_progress', then=1), output_field=IntegerField())), Value(0)),
                    completed_tasks=Coalesce(Count(Case(When(status='completed', then=1), output_field=IntegerField())), Value(0)),
                    approved_tasks=Coalesce(Count(Case(When(status='approved', then=1), output_field=IntegerField())), Value(0))
                )
                
                # Super fast response
                return Response({
                    'statistics': task_stats,
                })
                
            # Check if we only need stats (faster loading)
            stats_only = request.query_params.get('stats_only', 'false').lower() == 'true'

            # Get client's tasks with optimized query - only select fields we need
            if stats_only:
                # For stats-only, we just need the status field
                client_tasks = Task.objects.filter(assigned_to=request.user).values('status')
                
                # Get statistics in a single efficient query using annotate
                task_stats = client_tasks.aggregate(
                    total_tasks=Count('id'),
                    pending_tasks=Count(Case(When(status='pending', then=1), output_field=IntegerField())),
                    completed_tasks=Count(Case(When(status='completed', then=1), output_field=IntegerField())),
                    in_progress_tasks=Count(Case(When(status='in_progress', then=1), output_field=IntegerField())),
                    approved_tasks=Count(Case(When(status='approved', then=1), output_field=IntegerField()))
                )
                
                # Just return the statistics for fast loading
                return Response({
                    'statistics': task_stats,
                })
            
            # Full response with everything
            client_tasks = Task.objects.filter(assigned_to=request.user).select_related('service_engineer')
            
            # Get statistics
            task_stats = client_tasks.aggregate(
                total_tasks=Count('id'),
                pending_tasks=Count(Case(When(status='pending', then=1), output_field=IntegerField())),
                completed_tasks=Count(Case(When(status='completed', then=1), output_field=IntegerField())),
                in_progress_tasks=Count(Case(When(status='in_progress', then=1), output_field=IntegerField())),
                approved_tasks=Count(Case(When(status='approved', then=1), output_field=IntegerField()))
            )
            
            # Get recent tasks with optimized order
            recent_tasks = client_tasks.order_by('-updated_at')[:5]
            
            # Use serializer with specific fields to reduce payload size
            recent_tasks_data = []
            for task in recent_tasks:
                recent_tasks_data.append({
                    'id': task.id,
                    'global_id': task.global_id,
                    'site_name': task.site_name,
                    'cluster': task.cluster,
                    'status': task.status,
                    'date': task.date,
                    'updated_at': task.updated_at,
                    'service_type': task.service_type,
                })
            
            # Get tasks by status
            tasks_by_status = client_tasks.values('status').annotate(count=Count('id'))
            
            # Return optimized payload
            return Response({
                'statistics': task_stats,
                'recent_tasks': recent_tasks_data,
                'tasks_by_status': tasks_by_status,
            })
        except Exception as e:
            # Log the error
            print(f"Error in client dashboard: {str(e)}")
            print(traceback.format_exc())
            
            # Return a simple response with error details
            return Response({
                'error': 'An error occurred while loading the dashboard',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ReportViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows reports to be viewed or edited.
    """
    serializer_class = ReportSerializer
    permission_classes = [permissions.IsAuthenticated]
    http_method_names = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']

    def get_queryset(self):
        user = self.request.user
        
        # Check if user has a profile
        try:
            profile = UserProfile.objects.get(user=user)
            
            # Admin can see all reports (using profile.user_type instead of is_staff)
            if profile.user_type in ['admin', 'super_admin']:
                return Report.objects.all().order_by('-created_at')
            elif profile.user_type == 'client':  # Client can see only their reports
                return Report.objects.filter(submitted_by=user).order_by('-created_at')
            else:  # Service engineers can see reports for tasks assigned to them
                return Report.objects.filter(
                    task__assigned_to=user
                ).order_by('-created_at')
        except UserProfile.DoesNotExist:
            # Return empty queryset if user doesn't have a profile
            return Report.objects.none()

    def perform_create(self, serializer):
        report = serializer.save(submitted_by=self.request.user)
        
        # Update task status when report is submitted
        if report.task:
            report.task.status = 'pending'
            report.task.save()

    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve a report (admin only)"""
        try:
            # Verify user is admin
            profile = UserProfile.objects.get(user=request.user)
            if profile.user_type not in ['admin', 'super_admin']:
                return Response(
                    {'error': 'Only admins can approve reports'}, 
                    status=status.HTTP_403_FORBIDDEN
                )
                
            # Get the report
            report = self.get_object()
            
            # Update report status to reviewed
            report.status = 'reviewed'
            report.save()
            
            # Update task status to approved
            if report.task:
                report.task.status = 'approved'
                report.task.save()
                print(f"Task {report.task.id} status updated to approved")
            
            return Response({
                'success': True,
                'message': f'Report "{report.title}" has been approved',
                'report_id': report.id,
                'report_status': report.status,
                'task_id': report.task.id if report.task else None,
                'task_status': report.task.status if report.task else None
            })
            
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'User profile not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            print(f"Error in approve method: {str(e)}")
            return Response(
                {'error': f'Failed to approve report: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject a report (admin only)"""
        try:
            # Verify user is admin
            profile = UserProfile.objects.get(user=request.user)
            if profile.user_type not in ['admin', 'super_admin']:
                return Response(
                    {'error': 'Only admins can reject reports'}, 
                    status=status.HTTP_403_FORBIDDEN
                )
                
            # Get the report
            report = self.get_object()
            
            # Get rejection reason
            rejection_reason = request.data.get('rejection_reason', '')
            if not rejection_reason:
                return Response(
                    {'error': 'Rejection reason is required'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Update report status to rejected
            report.status = 'rejected'
            report.rejection_reason = rejection_reason
            report.save()
            
            # Keep task status as pending for resubmission
            if report.task and report.task.status != 'pending':
                report.task.status = 'pending'
                report.task.save()
            
            return Response({
                'success': True,
                'message': f'Report "{report.title}" has been rejected',
                'report_id': report.id,
                'status': report.status,
                'rejection_reason': report.rejection_reason,
                'task_status': report.task.status if report.task else None
            })
            
        except UserProfile.DoesNotExist:
            return Response(
                {'error': 'User profile not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {'error': f'Failed to reject report: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ClientProfileViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        # Check if user is client
        try:
            profile = UserProfile.objects.get(user=request.user)
            if profile.user_type != 'client':
                return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)

        # Get client data
        user = request.user
        data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'phone': getattr(user, 'phone', None),
            'company': getattr(user, 'company', None),
            'address': getattr(user, 'address', None),
            'date_joined': user.date_joined.strftime('%Y-%m-%d'),
            'is_active': user.is_active,
        }
        return Response(data)

    def update(self, request):
        # Check if user is client
        try:
            profile = UserProfile.objects.get(user=request.user)
            if profile.user_type != 'client':
                return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
        except UserProfile.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=status.HTTP_404_NOT_FOUND)

        user = request.user
        serializer = UserSerializer(user, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
