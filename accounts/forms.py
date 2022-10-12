from django import forms
from django.contrib.auth import authenticate
from django.contrib.auth.forms import UserCreationForm

from accounts.models import User



class EmployeeRegistrationForm(UserCreationForm):

    def __init__(self, *args, **kwargs):
        super(EmployeeRegistrationForm, self).__init__(*args, **kwargs)
        self.fields['first_name'].label = "Prénom"
        self.fields['last_name'].label = "Nom"
        self.fields['password1'].label = "Mot de Passe"
        self.fields['password2'].label = "Confirmer Mot de Passe"


        self.fields['first_name'].widget.attrs.update(
            {
                'placeholder': 'Entrer le prénom',
            }
        )
        self.fields['last_name'].widget.attrs.update(
            {
                'placeholder': 'Entrer le nom',
            }
        )
        self.fields['email'].widget.attrs.update(
            {
                'placeholder': 'Entrer Email',
            }
        )
        self.fields['password1'].widget.attrs.update(
            {
                'placeholder': 'Entrer le Mot de Passe',
            }
        )
        self.fields['password2'].widget.attrs.update(
            {
                'placeholder': 'Confirmer Mot de Passe',
            }
        )

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password1', 'password2']
        error_messages = {
            'first_name': {
                'required': 'First name is required',
                'max_length': 'Name is too long'
            },
            'last_name': {
                'required': 'Last name is required',
                'max_length': 'Last Name is too long'
            }
        }

    def save(self, commit=True):
        user = super(UserCreationForm, self).save(commit=False)
        user.role = "employee"
        if commit:
            user.save()
        return user


class EmployerRegistrationForm(UserCreationForm):

    def __init__(self, *args, **kwargs):
        super(EmployerRegistrationForm, self).__init__(*args, **kwargs)
        self.fields['first_name'].label = "Nom de l'entreprise"
        self.fields['last_name'].label = "Adresse de l'entreprise"
        self.fields['password1'].label = "Mot de Passe"
        self.fields['password2'].label = "Confirmer le Mot de Passe"

        self.fields['first_name'].widget.attrs.update(
            {
                'placeholder': 'Entrer nom entreprise',
            }
        )
        self.fields['last_name'].widget.attrs.update(
            {
                'placeholder': 'Entrer adresse entreprise',
            }
        )
        self.fields['email'].widget.attrs.update(
            {
                'placeholder': 'Entrer adresse mail',
            }
        )
        self.fields['password1'].widget.attrs.update(
            {
                'placeholder': 'Entrer Mot de Passe',
            }
        )
        self.fields['password2'].widget.attrs.update(
            {
                'placeholder': 'Confirmer Mot de Passe',
            }
        )

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'password1', 'password2']
        error_messages = {
            'first_name': {
                'required': 'Vous devez rentrer un prénom',
                'max_length': 'Le prénom est trop long'
            },
            'last_name': {
                'required': 'Vous devez rentrer un nom',
                'max_length': 'Le nom est trop long'
            }
        }

    def save(self, commit=True):
        user = super(UserCreationForm, self).save(commit=False)
        user.role = "employer"
        if commit:
            user.save()
        return user


class UserLoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(
        label="Mot de passe",
        strip=False,
        widget=forms.PasswordInput,
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None
        self.fields['email'].widget.attrs.update({'placeholder': 'Saisissez votre adresse mail'})
        self.fields['password'].widget.attrs.update({'placeholder': 'Saisissez votre Mot de Passe'})

    def clean(self, *args, **kwargs):
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")

        if email and password:
            self.user = authenticate(email=email, password=password)

            if self.user is None:
                raise forms.ValidationError("L'utilisateur n'existe pas.")
            if not self.user.check_password(password):
                raise forms.ValidationError("Le Mot de Passe ne correspond pas.")
            if not self.user.is_active:
                raise forms.ValidationError("L'utilisateur n'est plus actif.")

        return super(UserLoginForm, self).clean(*args, **kwargs)

    def get_user(self):
        return self.user


class EmployeeProfileUpdateForm(forms.ModelForm):

    def __init__(self, *args, **kwargs):
        super(EmployeeProfileUpdateForm, self).__init__(*args, **kwargs)
        self.fields['first_name'].widget.attrs.update(
            {
                'placeholder': 'Entrez le prénom',
            }
        )
        self.fields['last_name'].widget.attrs.update(
            {
                'placeholder': 'Entrez le nom',
            }
        )

    class Meta:
        model = User
        fields = ["first_name", "last_name"]
