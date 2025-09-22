from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.db import IntegrityError
from django.core.paginator import Paginator
from django.db.models import Count
from django.utils import timezone
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from datetime import timedelta
import re
from .models import UserProfile

# Assuming you have these models in your petition app
from petitions.models import Petition, Signature


def validate_password_strength(password):
    """
    Validate password strength with multiple criteria
    Returns tuple (is_valid, list_of_errors)
    """
    errors = []
    
    # Length check
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")

    if len(password) > 128:
        errors.append("Password must not exceed 128 characters.")
    
    # Character type checks
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter.")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter.")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one number.")
    
    if not re.search(r'[!@#$%^&*()_+=\[\]{};\':"\\|,.<>\/?~`-]', password):
        errors.append("Password must contain at least one special character (!@#$%^&*()_+=[]{}|;':\",./<>?~`-).")
    
    # Common patterns check
    if re.search(r'(.)\1{2,}', password):
        errors.append("Password must not contain more than 2 consecutive identical characters.")
    
    # Sequential characters check
    sequences = [
        'abcdefghijklmnopqrstuvwxyz',
        '0123456789',
        'qwertyuiop',
        'asdfghjkl',
        'zxcvbnm'
    ]
    
    password_lower = password.lower()
    for sequence in sequences:
        for i in range(len(sequence) - 3):
            if sequence[i:i+4] in password_lower or sequence[i:i+4][::-1] in password_lower:
                errors.append("Password must not contain sequential characters (e.g., '1234', 'abcd', 'qwerty').")
                break
    
    # Common weak passwords
    common_passwords = [
        'password', '123456789', 'qwerty123', 'admin123', 'welcome123',
        'password123', 'letmein123', 'monkey123', 'dragon123', 'master123'
    ]
    
    if password_lower in [p.lower() for p in common_passwords]:
        errors.append("Password is too common. Please choose a more unique password.")
    
    # Username similarity check would be done in the calling function
    
    return len(errors) == 0, errors


def validate_email_comprehensive(email, user_id=None):
    """
    Comprehensive email validation
    Returns tuple (is_valid, list_of_errors)
    """
    errors = []
    
    if not email:
        errors.append("Email is required.")
        return False, errors
    
    # Length check
    if len(email) > 254:
        errors.append("Email address is too long (maximum 254 characters).")
    
    # Basic format validation using Django's validator
    try:
        validate_email(email)
    except ValidationError:
        errors.append("Please enter a valid email address.")
        return False, errors
    
    # Additional format checks
    local_part, domain = email.rsplit('@', 1)
    
    # Local part validation
    if len(local_part) > 64:
        errors.append("Email address local part is too long (maximum 64 characters before @).")
    
    if local_part.startswith('.') or local_part.endswith('.'):
        errors.append("Email address cannot start or end with a period.")
    
    if '..' in local_part:
        errors.append("Email address cannot contain consecutive periods.")
    
    # Domain validation
    if len(domain) > 253:
        errors.append("Email domain is too long.")
    
    # Check for valid domain format
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', domain):
        errors.append("Email domain format is invalid.")
    
    # Check for suspicious patterns
    suspicious_patterns = [
        r'\.{2,}',  # Multiple consecutive dots
        r'^\.+',    # Starting with dots
        r'\.+$',    # Ending with dots
        r'@.*@',    # Multiple @ symbols
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, email):
            errors.append("Email format appears suspicious or invalid.")
            break
    
    # Disposable email domains (basic list)
    disposable_domains = [
        '10minutemail.com', 'tempmail.org', 'guerrillamail.com', 
        'mailinator.com', 'temp-mail.org', 'throwaway.email',
        'getnada.com', 'maildrop.cc', 'fakeinbox.com'
    ]
    
    if domain.lower() in disposable_domains:
        errors.append("Please use a permanent email address, not a temporary/disposable one.")
    
    # Check if email already exists (excluding current user for settings)
    existing_query = User.objects.filter(email__iexact=email)
    if user_id:
        existing_query = existing_query.exclude(id=user_id)
    
    if existing_query.exists():
        errors.append("This email address is already registered with another account.")
    
    return len(errors) == 0, errors


def login_view(request):
    """Handle user login"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if not username or not password:
            messages.error(request, 'Please provide both username and password.')
            return render(request, 'registration/login.html')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            messages.success(request, f'Welcome back, {user.get_full_name() or user.username}!')
            
            # Redirect to next page if specified, otherwise dashboard
            next_url = request.GET.get('next', 'dashboard')
            return redirect(next_url)
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'registration/login.html')


def signup_view(request):
    """Handle user registration with intense validation"""
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip().lower()
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        disability_type = request.POST.get('disabilities', '')
        
        # Collect all validation errors
        validation_errors = []
        
        # Required fields validation
        if not username:
            validation_errors.append('Username is required.')
        elif len(username) < 3:
            validation_errors.append('Username must be at least 3 characters long.')
        elif len(username) > 30:
            validation_errors.append('Username must not exceed 30 characters.')
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            validation_errors.append('Username can only contain letters, numbers, and underscores.')
        elif User.objects.filter(username=username).exists():
            validation_errors.append('Username already exists. Please choose another.')
        
        if not password:
            validation_errors.append('Password is required.')
        elif not confirm_password:
            validation_errors.append('Password confirmation is required.')
        elif password != confirm_password:
            validation_errors.append('Passwords do not match.')
        else:
            # Password strength validation
            is_password_valid, password_errors = validate_password_strength(password)
            if not is_password_valid:
                validation_errors.extend(password_errors)
            
            # Check if password contains username
            if username.lower() in password.lower():
                validation_errors.append('Password must not contain your username.')
            
            # Check if password contains name parts
            if first_name and len(first_name) > 2 and first_name.lower() in password.lower():
                validation_errors.append('Password must not contain your first name.')
            
            if last_name and len(last_name) > 2 and last_name.lower() in password.lower():
                validation_errors.append('Password must not contain your last name.')
        
        # Email validation
        if email:
            is_email_valid, email_errors = validate_email_comprehensive(email)
            if not is_email_valid:
                validation_errors.extend(email_errors)
        else:
            validation_errors.append('Email is required.')
        
        # Name validation
        if first_name and len(first_name) > 50:
            validation_errors.append('First name must not exceed 50 characters.')
        
        if last_name and len(last_name) > 50:
            validation_errors.append('Last name must not exceed 50 characters.')
        
        # If there are validation errors, return with errors
        if validation_errors:
            for error in validation_errors:
                messages.error(request, error)
            return render(request, 'registration/signup.html', {
                'form_data': request.POST
            })
        
        try:
            # Create user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,    
            )
            profile = UserProfile.objects.create(
                user=user,
                disability_type=disability_type,
                prefers_high_contrast=False,
                prefers_large_text=False
            )
            
            # Log the user in immediately
            login(request, user)
            messages.success(request, 'Account created successfully! Welcome to the platform.')
            return redirect('dashboard')
            
        except IntegrityError:
            messages.error(request, 'An error occurred while creating your account. Please try again.')
    
    return render(request, 'registration/signup.html')


@login_required
def dashboard(request):
    """User dashboard with overview of petitions and signatures"""
    user = request.user
    
    # Get user's petitions
    my_petitions = Petition.objects.filter(creator=user).order_by('-created_at')
    
    # Get petitions user has signed
    my_signatures = Signature.objects.filter(user=user).select_related('petition').order_by('-signed_at')

    total_supporters = Signature.objects.filter(
        petition__in=my_petitions
    ).exclude(user=user).count()

    # Recent activity - last 30 days
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_petitions = my_petitions.filter(created_at__gte=thirty_days_ago)
    recent_signatures = my_signatures.filter(signed_at__gte=thirty_days_ago)
    
    # Statistics
    total_petitions_created = my_petitions.count()
    total_signatures_given = my_signatures.count()
    total_signatures_received = Signature.objects.filter(petition__creator=user).count()
    
    # Most successful petition (most signatures)
    most_successful_petition = my_petitions.annotate(
        signature_count=Count('signatures')
    ).order_by('-signature_count').first()
    
    # Recent popular petitions (not created by user)
    popular_petitions = Petition.objects.filter(
        is_active=True
    ).exclude(
        creator=user
    ).annotate(
        signature_count=Count('signatures')
    ).order_by('-signature_count')[:5]
    
    context = {
        'user': user,
        'my_petitions': my_petitions[:5],  # Latest 5
        'my_signatures': my_signatures[:5],  # Latest 5
        'recent_petitions_count': recent_petitions.count(),
        'recent_signatures_count': recent_signatures.count(),
        'total_petitions_created': total_petitions_created,
        'total_signatures_given': total_signatures_given,
        'total_signatures_received': total_signatures_received,
        'most_successful_petition': most_successful_petition,
        'popular_petitions': popular_petitions,
        'total_supporters': total_supporters,
    }
    
    return render(request, 'dashboard.html', context)


@login_required
def change_password(request):
    """Change user password with intense validation"""
    if request.method == 'POST':
        current_password = request.POST.get('current_password', '')
        new_password = request.POST.get('new_password', '')
        confirm_password = request.POST.get('confirm_password', '')
        
        validation_errors = []
        
        # Validate current password
        if not current_password:
            validation_errors.append('Current password is required.')
        elif not request.user.check_password(current_password):
            validation_errors.append('Current password is incorrect.')
        
        # Validate new password
        if not new_password:
            validation_errors.append('New password is required.')
        elif not confirm_password:
            validation_errors.append('Password confirmation is required.')
        elif new_password != confirm_password:
            validation_errors.append('New passwords do not match.')
        elif new_password == current_password:
            validation_errors.append('New password must be different from current password.')
        else:
            # Password strength validation
            is_password_valid, password_errors = validate_password_strength(new_password)
            if not is_password_valid:
                validation_errors.extend(password_errors)
            
            # Check if password contains user info
            if request.user.username.lower() in new_password.lower():
                validation_errors.append('Password must not contain your username.')
            
            if request.user.first_name and len(request.user.first_name) > 2:
                if request.user.first_name.lower() in new_password.lower():
                    validation_errors.append('Password must not contain your first name.')
            
            if request.user.last_name and len(request.user.last_name) > 2:
                if request.user.last_name.lower() in new_password.lower():
                    validation_errors.append('Password must not contain your last name.')
            
            if request.user.email and request.user.email.split('@')[0].lower() in new_password.lower():
                validation_errors.append('Password must not contain parts of your email address.')
        
        if validation_errors:
            for error in validation_errors:
                messages.error(request, error)
            return render(request, 'accounts/change_password.html')
        
        # Update password
        request.user.set_password(new_password)
        request.user.save()
        
        messages.success(request, 'Password changed successfully! Please log in with your new password.')
        return redirect('login')  # Redirect to login to re-authenticate
    
    return render(request, 'accounts/change_password.html')


def logout_view(request):
    """Handle user logout"""
    if request.user.is_authenticated:
        username = request.user.get_full_name() or request.user.username
        logout(request)
        messages.success(request, f'Goodbye, {username}! You have been logged out.')
    
    return redirect('login')


@login_required
def account_stats(request):
    """Detailed account statistics page"""
    user = request.user
    
    # Get all user's petitions with signature counts
    my_petitions = Petition.objects.filter(creator=user).annotate(
        signature_count=Count('signatures')
    ).order_by('-signature_count')
    
    # Get signatures with petition info
    my_signatures = Signature.objects.filter(user=user).select_related('petition')
    
    # Monthly activity for the past year
    one_year_ago = timezone.now() - timedelta(days=365)
    monthly_petitions = {}
    monthly_signatures = {}
    
    for petition in Petition.objects.filter(creator=user, created_at__gte=one_year_ago):
        month_key = petition.created_at.strftime('%Y-%m')
        monthly_petitions[month_key] = monthly_petitions.get(month_key, 0) + 1
    
    for signature in Signature.objects.filter(user=user, signed_at__gte=one_year_ago):
        month_key = signature.signed_at.strftime('%Y-%m')
        monthly_signatures[month_key] = monthly_signatures.get(month_key, 0) + 1
    
    # Pagination for petitions
    paginator = Paginator(my_petitions, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'my_petitions': page_obj,
        'my_signatures': my_signatures,
        'monthly_petitions': monthly_petitions,
        'monthly_signatures': monthly_signatures,
        'total_signatures_received': sum(p.signature_count for p in my_petitions),
    }
    
    return render(request, 'accounts/account_stats.html', context)


@login_required
def settings_view(request):
    """User settings with intense email validation"""
    # Get the profile; create if it doesn't exist
    profile, created = UserProfile.objects.get_or_create(user=request.user)

    if request.method == "POST":
        validation_errors = []
        
        # Get form data
        first_name = request.POST.get("first_name", "").strip()
        last_name = request.POST.get("last_name", "").strip()
        email = request.POST.get("email", "").strip().lower()
        username = request.POST.get("username", "").strip()
        full_name = request.POST.get("full_name", "").strip()
        disability_type = request.POST.get("disability_type", "")
        
        # Username validation
        if not username:
            validation_errors.append('Username is required.')
        elif len(username) < 3:
            validation_errors.append('Username must be at least 3 characters long.')
        elif len(username) > 30:
            validation_errors.append('Username must not exceed 30 characters.')
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            validation_errors.append('Username can only contain letters, numbers, and underscores.')
        elif username != request.user.username:
            # Check if new username exists
            if User.objects.filter(username=username).exists():
                validation_errors.append('Username already exists. Please choose another.')
        
        # Email validation
        if email:
            is_email_valid, email_errors = validate_email_comprehensive(email, request.user.id)
            if not is_email_valid:
                validation_errors.extend(email_errors)
        else:
            validation_errors.append('Email is required.')
        
        # Name validation
        if first_name and len(first_name) > 50:
            validation_errors.append('First name must not exceed 50 characters.')
        
        if last_name and len(last_name) > 50:
            validation_errors.append('Last name must not exceed 50 characters.')
        
        if full_name and len(full_name) > 100:
            validation_errors.append('Full name must not exceed 100 characters.')
        
        # Name format validation (only letters, spaces, hyphens, apostrophes)
        name_pattern = r"^[a-zA-Z\s\-']+$"
        if first_name and not re.match(name_pattern, first_name):
            validation_errors.append('First name can only contain letters, spaces, hyphens, and apostrophes.')
        
        if last_name and not re.match(name_pattern, last_name):
            validation_errors.append('Last name can only contain letters, spaces, hyphens, and apostrophes.')
        
        if full_name and not re.match(name_pattern, full_name):
            validation_errors.append('Full name can only contain letters, spaces, hyphens, and apostrophes.')
        
        if validation_errors:
            for error in validation_errors:
                messages.error(request, error)
        else:
            try:
                # Update user fields
                request.user.first_name = first_name
                request.user.last_name = last_name
                request.user.email = email
                request.user.username = username
                request.user.save()

                # Update profile fields
                profile.full_name = full_name
                profile.disability_type = disability_type
                profile.prefers_high_contrast = bool(request.POST.get("prefers_high_contrast"))
                profile.prefers_large_text = bool(request.POST.get("prefers_large_text"))
                profile.save()
                
                messages.success(request, 'Settings updated successfully!')
                return redirect("settings")
                
            except IntegrityError:
                messages.error(request, 'An error occurred while updating your settings. Please try again.')

    context = {"profile": profile}
    return render(request, "accounts/settings.html", context)