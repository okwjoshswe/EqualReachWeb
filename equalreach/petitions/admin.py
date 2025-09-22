from django.contrib import admin
from .models import Petition, Signature

@admin.register(Petition)
class PetitionAdmin(admin.ModelAdmin):
    list_display = ('title', 'creator', 'category', 'goal', 'total_signatures', 'is_active', 'created_at')
    list_filter = ('is_active', 'category', 'created_at')
    search_fields = ('title', 'description', 'creator__username')
    date_hierarchy = 'created_at'
    
    # Optional: Add this method if you want to show progress in admin too
    def get_progress(self, obj):
        return f"{obj.progress_percentage():.1f}%"
    get_progress.short_description = "Progress"

@admin.register(Signature)
class SignatureAdmin(admin.ModelAdmin):
    list_display = ('user', 'petition', 'signed_at')
    list_filter = ('signed_at',)
    search_fields = ('user__username', 'petition__title', 'comment')