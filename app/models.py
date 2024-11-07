from django.db import models
from django.conf import settings

class Scan(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    domain_name = models.CharField(max_length=255)
    tool_used = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True) 

    def __str__(self):
        username = self.user.username if self.user else "Anonymous"
        return f"{username} - {self.domain_name} ({self.tool_used})"

class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)  # Ensures IPs are unique
    reason = models.CharField(max_length=255, blank=True, null=True)  # Optional reason for blocking
    blocked_at = models.DateTimeField(auto_now_add=True)  # Timestamp for when the IP was blocked

    def __str__(self):
        return f"{self.ip_address} - {self.reason or 'No reason specified'}"
