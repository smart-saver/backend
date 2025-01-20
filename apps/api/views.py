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
from django.http import JsonResponse
from azure.ai.inference import ChatCompletionsClient
from azure.ai.inference.models import SystemMessage, UserMessage
from azure.core.credentials import AzureKeyCredential
import environ

env = environ.Env()

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
        
class LogoutView(APIView):
    def post(self, request):
        response = Response({'message': 'Logged out successfully'}, status=200)
        response.delete_cookie(AUTH_COOKIE_KEY)
        return response

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
        

class TransactionDateView(APIView):
    @swagger_auto_schema(
        responses={200: TransactionSerializer(many=True)}
    )
    def get(self, request):
        transactions = Transaction.objects.filter(user=request.user).order_by('date')
        grouped_transactions = {}
        
        for transaction in transactions:
            date_key = transaction.date.date()  # Assuming 'date' is a DateTimeField
            if date_key not in grouped_transactions:
                grouped_transactions[date_key] = []
            grouped_transactions[date_key].append(transaction)

        # Prepare a list of dictionaries for serialization
        serialized_data = [
            {
                'date': date_key,
                'transactions': TransactionSerializer(transactions, many=True).data,
                'total_buy': sum(int(transaction.amount) for transaction in transactions if transaction.type == 'buy'),
                'total_sell': sum(int(transaction.amount) for transaction in transactions if transaction.type == 'sell'),
            }
            for date_key, transactions in grouped_transactions.items()
        ]

        return Response(serialized_data)

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
        

class ImportExportTransactionsView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Export transactions to CSV",
        responses={200: "CSV file"}
    )
    def get(self, request):
        import csv
        from django.http import HttpResponse
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="transactions.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['amount', 'description', 'date', 'type', 'category'])
        
        transactions = Transaction.objects.filter(user=request.user)
        for transaction in transactions:
            writer.writerow([
                transaction.amount,
                transaction.description,
                transaction.date,
                transaction.type,
                transaction.category.id if transaction.category else ''
            ])
            
        return response

    @swagger_auto_schema(
        operation_description="Import transactions from CSV",
        responses={201: "Transactions imported successfully", 400: "Invalid CSV format"}
    )
    def post(self, request):
        import csv
        import io
        
        if 'file' not in request.FILES:
            return Response({'error': 'No file uploaded'}, status=400)
            
        csv_file = request.FILES['file']
        if not csv_file.name.endswith('.csv'):
            return Response({'error': 'File must be CSV format'}, status=400)
            
        try:
            decoded_file = csv_file.read().decode('utf-8')
            io_string = io.StringIO(decoded_file)
            reader = csv.DictReader(io_string)
            
            for row in reader:
                category = None
                if row.get('category'):
                    category, _ = Category.objects.get_or_create(name=row['category'])
                    
                Transaction.objects.create(
                    user=request.user,
                    amount=row['amount'],
                    description=row.get('description', ''),
                    type=row.get('type', 'buy'),
                    category=category,
                    date=row.get('date')
                )
                
            return Response({'message': 'Transactions imported successfully'}, status=201)
            
        except Exception as e:
            return Response({'error': str(e)}, status=400)


class ChatbotView(APIView):
    def post(self, request):
        user_message = request.data.get("message", "")
        transactions = Transaction.objects.filter(user=request.user)
        
        if not user_message:
            return JsonResponse({'error': 'Message is required'}, status=400)

        # Initialize the Azure ChatCompletionsClient
        client = ChatCompletionsClient(
            endpoint="https://models.inference.ai.azure.com",
            credential=AzureKeyCredential(""),
        )

        print(user_message)


        user_transactions = [{"amount": t.amount, "description": t.description, "type": t.type, "category": t.category.name if t.category else None, "date": t.date} for t in transactions]

        print(user_message + '\n\n' + str(user_transactions))

        try:
            # Prepare the response from the model
            response = client.complete(
                messages=[
                    SystemMessage(content="""
                        You are a financial assistant AI strictly tasked with analyzing user transactions. I will provide you with a list of transactions in the following format:
                        
                        ### INTRODUCTION
                        Based on this input, calculate and provide the following analysis:
                        1. Total Transactions: The total number of transactions.
                        2. Total Amount: The sum of the amounts of all transactions.
                        3. Transaction Types Breakdown: A count of transactions grouped by their type (e.g., "income", "expense").
                        4.  Category Breakdown: A count of transactions grouped by category, excluding any null categories.
                        
                        ###RULES
                        Only use the provided data to calculate and analyze.
                    """),
                    UserMessage(content=user_message + '\n\n' + str(user_transactions)),
                ],
                model="Llama-3.3-70B-Instruct",
                temperature=0.8,
                max_tokens=2048,
                top_p=0.1
            )

            # Return the response content
            return JsonResponse({'response': response.choices[0].message.content})

        except Exception as e:
            # Log the error for debugging
            return JsonResponse({'error': str(e)}, status=400)


