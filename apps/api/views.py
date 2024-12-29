from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from .serializers import UserSerializer, TransactionSerializer, CategorySerializer, TargetSerializer
from apps.transaction.models import Transaction, Category, Target
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from apps.account.auth_backends import AUTH_COOKIE_KEY
from drf_yasg.utils import swagger_auto_schema

User = get_user_model()

class LoginView(APIView):
    @swagger_auto_schema(
        responses={200: UserSerializer}
    )
    def get(self, request):
        try:
            token = request.COOKIES.get(AUTH_COOKIE_KEY)
            if not token:
                return Response({'error': 'Not authenticated'}, status=401)
            
            token_obj = Token.objects.get(key=token)
            user = token_obj.user
            
            serializer = UserSerializer(user)
            return Response(serializer.data)
            
        except Token.DoesNotExist:
            return Response({'error': 'Invalid token'}, status=401)
        
    @swagger_auto_schema(
        request_body=UserSerializer,
        responses={201: "Item created successfully", 400: "Invalid data"},
    )
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'Invalid credentials'}, status=401)

        if not user.check_password(password):
            return Response({'error': 'Invalid credentials'}, status=401)

        if user.is_active:
            serializer = UserSerializer(user)
            token, created = Token.objects.get_or_create(user=user)
            response = Response({
                    'token': token.key,
                    'user': serializer.data
            })
            response.set_cookie(AUTH_COOKIE_KEY, token.key)
            return response
        else:
            return Response({'error': 'User account is disabled'}, status=401)

class SignupView(APIView):
    @swagger_auto_schema(
        request_body=UserSerializer,
        responses={201: "Item created successfully", 400: "Invalid data"},
    )
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        username = request.data.get('username')

        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email already registered'}, status=400)

        user = User.objects.create_user(
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            username=username
        )

        serializer = UserSerializer(user)
        token, created = Token.objects.get_or_create(user=user)
        response = Response({
                'token': token.key,
                'user': serializer.data
        }, status=201)
        response.set_cookie(AUTH_COOKIE_KEY, token.key)
        return response
    


class TransactionView(APIView):
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        responses={200: TransactionSerializer(many=True)}
    )
    def get(self, request, pk=None):
        if pk:
            try:
                transaction = Transaction.objects.get(pk=pk, user=request.user)
                serializer = TransactionSerializer(transaction)
                return Response(serializer.data)
            except Transaction.DoesNotExist:
                return Response({'error': 'Transaction not found'}, status=404)
        else:
            transactions = Transaction.objects.filter(user=request.user)
            serializer = TransactionSerializer(transactions, many=True)
            return Response(serializer.data)
    
    @swagger_auto_schema(
        request_body=TransactionSerializer,
        responses={201: TransactionSerializer(), 400: "Invalid data"}
    )
    def post(self, request):
        data = request.data.copy()
        data['user'] = request.user.id
        
        serializer = TransactionSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)


    @swagger_auto_schema(
        request_body=TransactionSerializer,
        responses={200: TransactionSerializer(), 400: "Invalid data", 404: "Transaction not found"}
    )
    def put(self, request, pk):
        try:
            transaction = Transaction.objects.get(pk=pk, user=request.user)
        except Transaction.DoesNotExist:
            return Response({'error': 'Transaction not found'}, status=404)

        data = request.data.copy()
        data['user'] = request.user.id
        
        serializer = TransactionSerializer(transaction, data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)


    @swagger_auto_schema(
        responses={204: "No Content", 404: "Transaction not found"}
    )
    def delete(self, request, pk):
        try:
            transaction = Transaction.objects.get(pk=pk, user=request.user)
            transaction.delete()
            return Response(status=204)
        except Transaction.DoesNotExist:
            return Response({'error': 'Transaction not found'}, status=404)
        

class CategoryView(APIView):
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        responses={200: CategorySerializer(many=True)}
    )
    def get(self, request, pk=None):
        if pk:
            try:
                category = Category.objects.get(pk=pk)
                serializer = CategorySerializer(category)
                return Response(serializer.data)
            except Category.DoesNotExist:
                return Response({'error': 'Category not found'}, status=404)
        
        categories = Category.objects.all()
        serializer = CategorySerializer(categories, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        request_body=CategorySerializer,
        responses={201: CategorySerializer(), 400: "Invalid data"}
    )
    def post(self, request):
        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

    @swagger_auto_schema(
        request_body=CategorySerializer,
        responses={200: CategorySerializer(), 400: "Invalid data", 404: "Category not found"}
    )
    def put(self, request, pk):
        try:
            category = Category.objects.get(pk=pk)
        except Category.DoesNotExist:
            return Response({'error': 'Category not found'}, status=404)
        
        serializer = CategorySerializer(category, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    @swagger_auto_schema(
        responses={204: "No Content", 404: "Category not found"}
    )
    def delete(self, request, pk):
        try:
            category = Category.objects.get(pk=pk)
            category.delete()
            return Response(status=204)
        except Category.DoesNotExist:
            return Response({'error': 'Category not found'}, status=404)


class TargetView(APIView):
    @swagger_auto_schema(
        responses={200: TargetSerializer(many=True)}
    )
    def get(self, request, pk=None):
        if pk:
            try:
                target = Target.objects.get(pk=pk)
                serializer = TargetSerializer(target)
                return Response(serializer.data)
            except Target.DoesNotExist:
                return Response({'error': 'Target not found'}, status=404)
        
        targets = Target.objects.all()
        serializer = TargetSerializer(targets, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        request_body=TargetSerializer,
        responses={201: TargetSerializer(), 400: "Invalid data"}
    )
    def post(self, request):
        serializer = TargetSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        return Response(serializer.errors, status=400)

    @swagger_auto_schema(
        request_body=TargetSerializer,
        responses={200: TargetSerializer(), 400: "Invalid data", 404: "Target not found"}
    )
    def put(self, request, pk):
        try:
            target = Target.objects.get(pk=pk)
        except Target.DoesNotExist:
            return Response({'error': 'Target not found'}, status=404)
        
        serializer = TargetSerializer(target, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    @swagger_auto_schema(
        responses={204: "No Content", 404: "Target not found"}
    )
    def delete(self, request, pk):
        try:
            target = Target.objects.get(pk=pk)
            target.delete()
            return Response(status=204)
        except Target.DoesNotExist:
            return Response({'error': 'Target not found'}, status=404)
