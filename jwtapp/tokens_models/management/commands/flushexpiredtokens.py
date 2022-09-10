from django.core.management.base import BaseCommand
from jwtapp.utils import aware_utcnow
from ...models import OutstandingToken


class Command(BaseCommand):
    help = "Стирает все истёкшие токены из базы данных"

    def handle(self, *args, **kwargs):
        OutstandingToken.objects.filter(expires_at__lte=aware_utcnow()).delete()
