from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):

    def get_full_name(self):
        return self.first_name + " - " + self.last_name

    def __str__(self):
        if self.first_name and self.last_name:
            return self.first_name + " - " + self.last_name
        return self.username
