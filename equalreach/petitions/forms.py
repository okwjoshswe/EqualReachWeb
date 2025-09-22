# filepath: c:\Users\Hp\Documents\EqualReach\equalreach\petitions\forms.py
from django import forms
from .models import Petition, Signature

class PetitionForm(forms.ModelForm):
    class Meta:
        model = Petition
        fields = ['title', 'description', 'category', 'goal']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 5}),
        }


class SignatureForm(forms.ModelForm):
    class Meta:
        model = Signature
        fields = ['comment']
        widgets = {
            'comment': forms.Textarea(attrs={'rows': 3, 'placeholder': 'Why do you support this petition?'})
        }


