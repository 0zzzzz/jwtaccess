from django.contrib import admin
from .models import BlacklistedToken, OutstandingToken

admin.site.register(BlacklistedToken)
admin.site.register(OutstandingToken)
