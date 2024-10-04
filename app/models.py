from django.db import models
from django.contrib.auth.models import User

class Scan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    domain_name = models.CharField(max_length=255)
    tool_used = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.tool_used} on {self.domain_name} by {self.user.username} at {self.timestamp}"
