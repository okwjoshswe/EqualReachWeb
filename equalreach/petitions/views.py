from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.core.paginator import Paginator
from .models import Petition, Signature
from .forms import PetitionForm


def petition_list(request):
    """Display all active petitions"""
    petitions = Petition.objects.filter(is_active=True).order_by('-created_at')
    
    # Add pagination
    paginator = Paginator(petitions, 10)  # Show 10 petitions per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'petitions': page_obj,
    }
    return render(request, 'petitions/petition_list.html', context)


def petition_detail(request, petition_id):
    """Display petition details and signatures"""
    petition = get_object_or_404(Petition, id=petition_id, is_active=True)
    signatures = petition.signatures.select_related('user').order_by('-signed_at')
    
    # Check if current user has signed
    user_signed = False
    if request.user.is_authenticated:
        user_signed = signatures.filter(user=request.user).exists()
    
    total_signatures = petition.total_signatures()
    progress_percentage = petition.progress_percentage()
    
    # Precompute stroke offset for the circular progress bar
    stroke_offset = 100 - progress_percentage if progress_percentage <= 100 else 0

    context = {
        'petition': petition,
        'signatures': signatures[:10],  # Show latest 10 signatures
        'user_signed': user_signed,
        'total_signatures': total_signatures,
        'progress_percentage': progress_percentage,
        'stroke_offset': stroke_offset,   # 👈 send this to template
    }
    return render(request, 'petitions/petition_detail.html', context)

@login_required
def my_petitions(request):
    """List petitions created by the logged-in user with stats"""
    user = request.user
    
    # Query petitions created by this user + add signature count
    petitions = Petition.objects.filter(creator=user).annotate(
        signature_count=Count("signatures")
    ).order_by("-created_at")
    
    # Paginate results (10 per page)
    paginator = Paginator(petitions, 10)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    
    context = {
        "page_obj": page_obj,
        "petitions": page_obj.object_list,  # optional for direct iteration
    }
    return render(request, "petitions/my_petitions.html", context)

@login_required
def sign_petition(request, petition_id):
    """Sign a petition"""
    petition = get_object_or_404(Petition, id=petition_id, is_active=True)
    
    if request.method == 'POST':
        # Check if user already signed
        if Signature.objects.filter(petition=petition, user=request.user).exists():
            messages.warning(request, 'You have already signed this petition.')
        else:
            # Create signature
            comment = request.POST.get('comment', '').strip()
            Signature.objects.create(
                petition=petition,
                user=request.user,
                comment=comment if comment else None
            )
            messages.success(request, 'Thank you for signing this petition!')
        
        return redirect('petitions:petition_detail', petition_id=petition.id)
    
    return render(request, 'petitions/sign_petition.html', {'petition': petition})

@login_required
def my_signatures(request):
    """List petitions signed by the logged-in user"""
    user = request.user
    
    # Get all signatures by this user, with related petition
    signatures = Signature.objects.filter(user=user).select_related("petition").order_by("-signed_at")
    
    # Paginate results (10 per page)
    paginator = Paginator(signatures, 10)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    
    context = {
        "page_obj": page_obj,
        "signatures": page_obj.object_list,
    }
    return render(request, "petitions/my_signatures.html", context)

@login_required
def petition_create(request):
    """Create a new petition"""
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        category = request.POST.get('category')
        goal = request.POST.get('goal', 100)
        
        # Basic validation
        if not title or not description:
            messages.error(request, 'Title and description are required.')
            return render(request, 'petitions/create_petition.html')
        
        try:
            goal = int(goal)
            if goal <= 0:
                raise ValueError
        except (ValueError, TypeError):
            goal = 100
        
        # Create petition
        petition = Petition.objects.create(
            creator=request.user,
            title=title.strip(),
            description=description.strip(),
            category=category.strip() if category else None,
            goal=goal
        )
        
        messages.success(request, 'Your petition has been created successfully!')
        return redirect('petitions:petition_detail', petition_id=petition.id)
    
    return render(request, 'petitions/create_petition.html')


@login_required
def my_petitions(request):
    """Display user's created petitions"""
    petitions = Petition.objects.filter(creator=request.user).order_by('-created_at')
    
    context = {
        'petitions': petitions,
    }
    return render(request, 'petitions/my_petitions.html', context)


@login_required
def edit_petition(request, petition_id):
    # Fetch the petition or return 404
    petition = get_object_or_404(Petition, id=petition_id, creator=request.user)
    
    if request.method == "POST":
        form = PetitionForm(request.POST, instance=petition)
        if form.is_valid():
            form.save()
            messages.success(request, "Petition updated successfully!")
            return redirect("dashboard")  # or redirect to petition detail page
    else:
        form = PetitionForm(instance=petition)
    
    context = {
        "form": form,
        "petition": petition
    }
    return render(request, "petitions/edit_petition.html", context)


@login_required
def delete_petition(request, petition_id):
    petition = get_object_or_404(Petition, id=petition_id, creator=request.user)

    if request.method == "POST":
        petition.delete()
        messages.success(request, "Petition deleted successfully.")
        return redirect("dashboard")  # go back to dashboard or petitions list

    return render(request, "petitions/delete_petition.html", {"petition": petition})