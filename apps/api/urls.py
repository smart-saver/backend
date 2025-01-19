
from django.urls import path, include
from .views import LoginView, SignupView, TransactionView, CategoryView, TargetView, ImportExportTransactionsView, LogoutView

urlpatterns = [
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/signup/', SignupView.as_view(), name='signup'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('transactions/', TransactionView.as_view(), name='transactions'),
    path('transactions/<int:pk>/', TransactionView.as_view(), name='transaction-detail'),
    path('categories/', CategoryView.as_view(), name='categories'),
    path('categories/<int:pk>/', CategoryView.as_view(), name='category-detail'),
    path('targets/', TargetView.as_view(), name='targets'),
    path('targets/<int:pk>/', TargetView.as_view(), name='target-detail'),
    path('transactions/import-export/', ImportExportTransactionsView.as_view(), name='import-export-transactions'),
]