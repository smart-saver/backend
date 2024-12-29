from django.contrib import admin
from .models import Transaction, Target, Category

admin.site.register(Transaction)
admin.site.register(Target)
admin.site.register(Category)
