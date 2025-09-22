# filepath: c:\Users\Hp\Documents\EqualReach\equalreach\petitions\urls.py
from django.urls import path
from . import views

app_name = 'petitions'

urlpatterns = [
    # path('', views.home, name='home'),
    path('petitions/', views.petition_list, name='petition_list'),
    path('petitions/<int:petition_id>/', views.petition_detail, name='petition_detail'),
    path('petitions/create/', views.petition_create, name='petition_create'),
    path('petitions/details/<int:petition_id>/', views.petition_detail, name='petition_detail'),
    path('petitions/<int:petition_id>/sign/', views.sign_petition, name='sign_petition'),
    path('my-petitions/', views.my_petitions, name='my_petitions'),
    path('my-signatures/', views.my_signatures, name='my_signatures'),
    path('petition/<int:petition_id>/edit/', views.edit_petition, name='edit_petition'),
    path('petition/<int:petition_id>/delete/', views.delete_petition, name='delete_petition'),
]