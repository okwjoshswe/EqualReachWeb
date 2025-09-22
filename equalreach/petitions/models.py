from django.db import models
from django.utils import timezone
from django.conf import settings


class Petition(models.Model):
    creator = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="petitions"
    )
    title = models.CharField(max_length=200)
    description = models.TextField()
    category = models.CharField(max_length=100, blank=True, null=True)  # optional
    goal = models.PositiveIntegerField(default=100)  # target number of signatures

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.title

    def total_signatures(self):
        return self.signatures.count()
    
    def supporters_count(self):
        return self.signatures.exclude(user=self.creator).count()

    def progress_percentage(self):
        if self.goal > 0:
            return (self.total_signatures() / self.goal) * 100
        return 0


class Signature(models.Model):
    petition = models.ForeignKey(
        Petition, on_delete=models.CASCADE, related_name="signatures"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="signatures"
    )
    comment = models.TextField(blank=True, null=True)
    signed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = ("petition", "user")  # Prevent duplicate signatures

    def __str__(self):
        return f"{self.user.username} signed {self.petition.title}"