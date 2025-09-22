from django.conf import settings
from django.db import models
from django.utils import timezone

class UserProfile(models.Model):
    # Link each profile to a Django User
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile")
    # Extra fields for your petition app
    full_name = models.CharField(max_length=150, blank=True, null=True)
    disability_type = models.CharField(max_length=100, blank=True, null=True)  
    profile_picture = models.ImageField(upload_to="profile_pics/", blank=True, null=True)
    # Accessibility preferences (optional, can expand later)
    prefers_high_contrast = models.BooleanField(default=False)
    prefers_large_text = models.BooleanField(default=False)
    # Metadata
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.user.username