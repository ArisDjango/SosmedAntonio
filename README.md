# Daftar isi - Bookmarks sosmed

- [ A. Chapter 4: Building a Social Website ](#A)
    - [ 1. Creating a social website project ](#A1)
        - [ 1.1. Starting your social website project ](#A11)
    - [ 2. Using the Django authentication framework ](#A2)
        - [ 2.1. Creating a login view ](#A21)
        - [ 2.2. Using Django authentication views ](#A22)
        - [ 2.3. Login and logout views ](#A23)
        - [ 2.4. Changing password views ](#A24)
        - [ 2.5. Resetting password views ](#A25)
    - [ 3. User registration and user profiles ](#A3)
        - [ 3.1. User registration ](#A31)
        - [ 3.2 Extending the user model ](#A32)
        - [ 3.3 Using a custom user model ](#A33)
        - [ 3.4 Using the messages framework ](#A34)
    - [ 4. Building a custom authentication backend ](#A4)
    - [ 5. Adding social authentication to your site ](#A5)
        - [ 5.1. Running the development server through HTTPS ](#A51)
        - [ 5.2. Authentication using Facebook ](#A52)
        - [ 5.3. Authentication using Twitter ](#A53)
        - [ 5.4. Authentication using Google ](#A54)

- [ B. Chapter 5: Sharing Content on Your Website ](#B)
    - [ 1. Creating an image bookmarking website ](#B1)
        - [ 1.1. Building the image model](#B11)
        - [ 1.2. Creating many-to-many relationships](#B12)
        - [ 1.3. Registering the image model in the administration site](#B13)
    - [ 2. Posting content from other websites](#B2)
        - [ 2.1 Cleaning form fields](#B21)
        - [ 2.2 Overriding the save() method of a ModelForm](#B22)
        - [ 2.3 Building a bookmarklet with jQuery](#B23)
    - [ 3. Creating a detail view for images](#B3)
    - [ 4. Creating image thumbnails using easy-thumbnails](#B4)
    - [ 5. Adding AJAX actions with jQuery](#B5)
        - [ 5.1. Loading jQuery](#B51)
        - [ 5.2. Cross-site request forgery in AJAX requests](#B52)
        - [ 5.3. Performing AJAX requests with jQuery](#B53)
    - [ 6. Creating custom decorators for your views](#B6)
    - [ 7. Adding AJAX pagination to your list views](#B7)

- [ C. Chapter 5: Tracking User Actions ](#C)
    - [ 1. Building a follow system ](#C1)
        - [ 1.1. Creating many-to-many relationships with an intermediary model ](#C11)
        - [ 1.2. Creating list and detail views for user profiles](#C12)
        - [ 1.3. Building an AJAX view to follow users](#C13)
    - [ 2. Building a generic activity stream application](#C2)
        - [ 2.1. Using the contenttypes framework](#C21)
        - [ 2.2. Adding generic relations to your models](#C22)
        - [ 2.3. Avoiding duplicate actions in the activity stream](#C23)
        - [ 2.4. Adding user actions to the activity stream](#C24)
        - [ 2.5. Displaying the activity stream](#C25)
        - [ 2.6. Optimizing QuerySets that involve related objects](#C26)
        - [ 2.7. Using select_related()](#C27)
        - [ 2.8 Using prefetch_related()](#C28)
        - [ 2.9. Creating templates for actions](#C29)
    - [ 3. Using signals for denormalizing counts](#C3)
        - [ 3.1. Working with signals](#C31)
        - [ 3.2. Application configuration classes](#C32)
    - [ 4. Using Redis for storing item views](#C4)
        - [ 4.1. Installing Redis](#C19)
        - [ 4.2. Using Redis with Python](#C20)
        - [ 4.3. Storing item views in Redis](#C21)
        - [ 4.4. Storing a ranking in Redis](#C22)
        - [ 4.5. Next steps with Redis](#C23)


<a name="A"></a>
## Chapter 4: Building a Social Website
<a name="A1"></a>
### Instalasi Django dan Struktur App
- Clone repo dan venv
    - cd PYTHON_FOLDER
    - git clone https://github.com/ArisDjango/SosmedAntonio.git
    - cd SosmedAntonio
    - python -m venv venv
    - Set-ExecutionPolicy Unrestricted -Scope Process
    - & d:/TUTORIAL/PYTHON/SosmedAntonio/venv/Scripts/Activate.ps1

- Instalasi Django
    - python.exe -m pip install --upgrade pip
    - pip install django

- membuat core project
    - django-admin startproject core
    - python migrate.py createsuperuser
    - rename root folder/core menjadi bookmarks
    - cd bookmarks
    - python manage.py migrate
    - python manage.py runserver
- Membuat app 'account'
    - python manage.py startapp account
    - register di settings.py, tempatkan paling atas agar bypass config
    ```
    'account.apps.AccountConfig',
    ```
- Mendesain account data model
    - model.py
    - python manage.py makemigrations account
    - python manage.py migrate


<a name="A2"></a>
### Using the Django authentication framework
    • AuthenticationMiddleware: Associates users with requests using sessions
    • SessionMiddleware: Handles the current session across requests
    The authentication framework also includes the following models:
        • User: A user model with basic fields; the main fields of this model are username, password, email, first_name, last_name, and is_active
        • Group: A group model to categorize users
        • Permission: Flags for users or groups to perform certain actions
<a name="A22"></a>
- Creating a login view
    - account/forms.py
        ```
            from django import forms

            class LoginForm(forms.Form):
                username = forms.CharField()
                password = forms.CharField(widget=forms.PasswordInput)
        ```
    - account/views.py
        ```
        from django.http import HttpResponse
        from django.shortcuts import render
        from django.contrib.auth import authenticate, login
        from .forms import LoginForm

        def user_login(request):
            if request.method == 'POST':
                form = LoginForm(request.POST)
                if form.is_valid():
                    cd = form.cleaned_data
                    user = authenticate(request, username=cd['username'], password=cd['password'])
                if user is not None:
                    if user.is_active:
                        login(request, user)
                        return HttpResponse('Authenticated ''successfully')
                    else:
                        return HttpResponse('Disabled account')
                else:
                    return HttpResponse('Invalid login')
            else:
                form = LoginForm()
            return render(request, 'account/login.html', {'form': form})

        ```
    - account/urls.py
        ```
        from django.urls import path
        from . import views

        urlpatterns = [
        # post views
            path('login/', views.user_login, name='login'),
        ]
        ```
    - core/urls.py
        ```
        from django.urls import path, include
        from django.contrib import admin

        urlpatterns = [
            path('admin/', admin.site.urls),
            path('account/', include('account.urls')),
            ]
        ```
    - Templates
        - Buat struktur file:
            - account/templates/
                - account
                    - login.html
                - base.html
        - Buat account/static/css/base.css
        - edit base.html
        ```
        {% load static %}
        <!DOCTYPE html>
        <html>
            <head>
                <title>{% block title %}{% endblock %}</title>
            <link href="{% static "css/base.css" %}" rel="stylesheet">
            </head>
            <body>
                <div id="header">
                    <span class="logo">Bookmarks</span>
                </div>
                <div id="content">
                    {% block content %}
                    {% endblock %}
                </div>
            </body>
        </html>
        ```
    - 127.0.0.1:8000/admin/
    - 127.0.0.1:8000/account/login
    - maka akan muncul halaman login

<a name="A23"></a>
- Using Django authentication views
    - docs : https://docs.djangoproject.com/en/3.0/topics/auth/default/#allauthentication-
    - otentifikasi bawaan django dihandle `django.contrib.auth.views`:
    - All of them are located in django.contrib.auth.views:
        - Login Logout
            • LoginView: menghandle form login user
            • LogoutView: Logout user

        - views untuk menghandle perubahan password :
            • PasswordChangeView: menghandel form perubahan password user
            • PasswordChangeDoneView: menghandle view ketika perubahan password berhasil redirect ke ...
        - views untuk menghandle reset password:
            • PasswordResetView: Allows users to reset their password. It generates a one-time-use link with a token and sends it to a user's email account.
            • PasswordResetDoneView: Tells users that an email—including a link to reset their password—has been sent to them.
            • PasswordResetConfirmView: Allows users to set a new password.
            • PasswordResetCompleteView: The success view that the user is redirected to after successfully resetting their password.

<a name="A24"></a>        
- Login and logout views
    - Edit account/urls.py
        ```
        from django.contrib.auth import views as auth_views
            ...
            # path('login/', views.user_login, name='login'),
            path('login/', auth_views.LoginView.as_view(), name='login'),
            path('logout/', auth_views.LogoutView.as_view(), name='logout'),
        ```
    - Buat templates/registration/login.html
        ```
        {% extends "base.html" %}
        {% block title %}Log-in{% endblock %}

        {% block content %}

            <h1>Log-in</h1>
            {% if form.errors %}
                <p>
                    Your username and password didn't match.
                    Please try again.
                </p>
            {% else %}
                <p>Please, use the following form to log-in:</p>
            {% endif %}

            <div class="login-form">
                <form action="{% url 'login' %}" method="post">
                    {{ form.as_p }}
                    {% csrf_token %}
                    <input type="hidden" name="next" value="{{ next }}" />
                    <p><input type="submit" value="Log-in"></p>
                </form>
            </div>
        {% endblock %}
        ```
    - Buat templates/registration/logged_out.html
        ```
        {% extends "base.html" %}
        {% block title %}Logged out{% endblock %}

        {% block content %}
        
        <h1>Logged out</h1>
        <p>
            You have been successfully logged out.
            You can <a href="{% url "login" %}">log-in again</a>.
        </p>

        {% endblock %}
        ```
    - Edit account/views.py
        ```
        from django.contrib.auth.decorators import login_required

        @login_required
        def dashboard(request):
        return render(request,'account/dashboard.html',{'section': 'dashboard'})
        ```
    - Buat templates/account/dashboard.html
        ```
        {% extends "base.html" %}
        {% block title %}Dashboard{% endblock %}
        {% block content %}
        <h1>Dashboard</h1>
        <p>Welcome to your dashboard.</p>
        {% endblock %}
        ```
    - Edit account/urls.py
        ```
        path('', views.dashboard, name='dashboard'),
        ```
    - Edit core/settings.py
        ```
        LOGIN_REDIRECT_URL = 'dashboard'
        LOGIN_URL = 'login'
        LOGOUT_URL = 'logout'
        ```
    - Edit templates/base.html
    ```
        <div id="header">
            <span class="logo">Bookmarks</span>
            {% if request.user.is_authenticated %}
            <ul class="menu">
                <li {% if section == 'dashboard' %}class='selected'{% endif %}>
                    <a href="{% url 'dashboard' %}">My dashboard</a>
                </li>
                <li {% if section == 'images' %}class='selected'{% endif %}>
                    <a href="#">Images</a>
                </li>
                    <li {% if section == 'people' %}class='selected'{% endif %}>
                <a href="#">People</a>
                </li>
            </ul>
            {% endif %}
            <span class="user">
            {% if request.user.is_authenticated %}
                Hello {{ request.user.first_name }},
                <a href="{% url 'logout' %}">Logout</a>
            {% else %}
                <a href="{% url 'login' %}">Log-in</a>
            {% endif %}
            </span>
        </div>
    ```
    - http://127.0.0.1:8000/account/login/

<a name="A25"></a>
- Changing password views
    - Edit account/urls.py
        ```
            # change password urls
            path('password_change/', auth_views.PasswordChangeView.as_view(), name='password_change'),
            path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(), name='password_change_done'),
        ```
    - Buat templates/registration/password_change_form.html
        ```
        {% extends "base.html" %}
        {% block title %}Change your password{% endblock %}
        
        {% block content %}
        <h1>Change your password</h1>
        <p>Use the form below to change your password.</p>
        <form method="post">
            {{ form.as_p }}
            <p><input type="submit" value="Change"></p>
            {% csrf_token %}
        </form>
        {% endblock %}
        ```
    - Buat templates/registration/password_change_done.html
        ```
        {% extends "base.html" %}
        {% block title %}Password changed{% endblock %}

        {% block content %}
        <h1>Password changed</h1>
        <p>Your password has been successfully changed.</p>
        {% endblock %}
        ```
    - http://127.0.0.1:8000/account/password_change/

<a name="A26"></a>
- Resetting password views
    - Edit account/urls.py
        ```
        # reset password urls
        path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
        path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
        path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
        path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
        ```
    - Buat file baru templates/registration/password_reset_form.html
        ```
        {% extends "base.html" %}
        {% block title %}Reset your password{% endblock %}

        {% block content %}
        <h1>Forgotten your password?</h1>
        <p>Enter your e-mail address to obtain a new password.</p>
        <form method="post">
            {{ form.as_p }}
            <p><input type="submit" value="Send e-mail"></p>
            {% csrf_token %}
        </form>
        {% endblock %}
        ```
    - Buat file baru templates/registration/password_reset_email.html
        ```
        Someone asked for password reset for email {{ email }}. Follow the link below:
        {{ protocol }}://{{ domain }}{% url "password_reset_confirm" uidb64=uid token=token %}
        Your username, in case you've forgotten: {{ user.get_username }}
        ```
    - Buat file baru templates/registration/password_reset_confirm.html
        ```
        {% extends "base.html" %}
        {% block title %}Reset your password{% endblock %}

        {% block content %}

        <h1>Reset your password</h1>
        {% if validlink %}
        <p>Please enter your new password twice:</p>
        <form method="post">
            {{ form.as_p }}
            {% csrf_token %}
            <p><input type="submit" value="Change my password" /></p>
        </form>
        {% else %}
            <p>The password reset link was invalid, possibly because it has already been used. Please request a new password reset.</p>
        {% endif %}

        {% endblock %}
        ```
    - Buat file baru templates/registration/password_reset_complete.html
        ```
        {% extends "base.html" %}
        {% block title %}Password reset{% endblock %}
        {% block content %}

        <h1>Password set</h1>
        <p>Your password has been set. You can
        <a href="{% url "login" %}">log in now</a></p>

        {% endblock %}
        ```
    - Edit registration/login.html
        ```
        <p><a href="{% url "password_reset" %}">Forgotten your password?</a></p>
        ```
    - pada core/settings.py, tambahkan setting email
        ```
        EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'
        ```
    - http://127.0.0.1:8000/account/login/, lalu coba 'forgotten your password'
    - Setelah fungsi reset berhasil, bisa mengganti semua auth.url menggunakan include (sama saja)
        ```
        from django.urls import path, include
        # ...
        urlpatterns = [
        # ...
        path('', include('django.contrib.auth.urls')),
        ]
        ```

- User registration and user profiles
- User registration
    - Edit account/forms.py
        ```
        class UserRegistrationForm(forms.ModelForm):
            password = forms.CharField(label='Password', widget=forms.PasswordInput)
            password2 = forms.CharField(label='Repeat password', widget=forms.PasswordInput)
            class Meta:
                model = User
                fields = ('username', 'first_name', 'email')
                def clean_password2(self):
                    cd = self.cleaned_data
                    if cd['password'] != cd['password2']:
                        raise forms.ValidationError('Passwords don\'t match.')
                    return cd['password2']
        ```
    - Edit account/Views.py
        ```
        from .forms import LoginForm, UserRegistrationForm

        def register(request):
            if request.method == 'POST':
                user_form = UserRegistrationForm(request.POST)
                if user_form.is_valid():
                    # Create a new user object but avoid saving it yet
                    new_user = user_form.save(commit=False)
                    # Set the chosen password
                    new_user.set_password(user_form.cleaned_data['password'])
                    # Save the User object
                    new_user.save()
                    return render(request,'account/register_done.html',{'new_user': new_user})
            else:
                user_form = UserRegistrationForm()
            return render(request,'account/register.html',{'user_form': user_form})
        ```
    - Edit account/urls.py
        ```
        path('register/', views.register, name='register'),
        ```
    - Buat template/account/register.html
        ```
        {% extends "base.html" %}
        {% block title %}Create an account{% endblock %}

        {% block content %}

        <h1>Create an account</h1>
        <p>Please, sign up using the following form:</p>
        <form method="post">
            {{ user_form.as_p }}
            {% csrf_token %}
            <p><input type="submit" value="Create my account"></p>
        </form>

        {% endblock %}
        ```
    - http://127.0.0.1:8000/account/register/
    - Edit registration/login.html
        ```
        <p>Please, use the following form to log-in. If you don't have an account <a href="{% url "register" % ">register here</a></p>
        ```

- Extending the user model
    - Edit account/models.py
        - docs: https://docs.djangoproject.com/en/3.0/topics/auth/customizing/#django.contrib.auth.get_user_model
        ```
        from django.db import models
        from django.conf import settings

        class Profile(models.Model):
            user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
            date_of_birth = models.DateField(blank=True, null=True)
            photo = models.ImageField(upload_to='users/%Y/%m/%d/', blank=True)

            def __str__(self):
                return f'Profile for user {self.user.username}'
        ```
    - pip install Pillow
    - core/settings.py
        ```
        MEDIA_URL = '/media/'
        MEDIA_ROOT = os.path.join(BASE_DIR, 'media/')
        ```
    - core/urls.py
        ```
        from django.conf import settings
        from django.conf.urls.static import static

        urlpatterns ...

        if settings.DEBUG: urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
        ```
    - python manage.py makemigrations
    - python manage.py migrate
    - admin.py
        ```
        from django.contrib import admin
        from .models import Profile

        @admin.register(Profile)
        class ProfileAdmin(admin.ModelAdmin):
            list_display = ['user', 'date_of_birth', 'photo']
        ```
        - http://127.0.0.1:8000/admin/
    - account/forms.py
        ```
        from .models import Profile

        class UserEditForm(forms.ModelForm):
            class Meta:
                model = User
                fields = ('first_name', 'last_name', 'email')
        class ProfileEditForm(forms.ModelForm):
            class Meta:
                model = Profile
                fields = ('date_of_birth', 'photo')
        ```
    - views.py
        ```
        from .models import Profile

        register()
            ...
            new_user.save()
            
            # Create the user profile
            Profile.objects.create(user=new_user)
        ```
    - views.py
        ```
        from .forms import ..., UserEditForm, ProfileEditForm

        @login_required
        def edit(request):
            if request.method == 'POST':
                user_form = UserEditForm(instance=request.user,
                data=request.POST)
                profile_form = ProfileEditForm(instance=request.user.profile,data=request.POST,files=request.FILES)
                if user_form.is_valid() and profile_form.is_valid():
                    user_form.save()
                    profile_form.save()
            else:
                user_form = UserEditForm(instance=request.user)
                profile_form = ProfileEditForm(instance=request.user.profile)
            return render(request,'account/edit.html',{'user_form': user_form,'profile_form': profile_form})
        ```
    - urls.py
        ```
        path('edit/', views.edit, name='edit'),
        ```
    - Buat templates/account/edit.html
        ```
        {% extends "base.html" %}
        {% block title %}Edit your account{% endblock %}

        {% block content %}

        <h1>Edit your account</h1>
        <p>You can edit your account using the following form:</p>
        <form method="post" enctype="multipart/form-data">
            {{ user_form.as_p }}
            {{ profile_form.as_p }}
            {% csrf_token %}
            <p><input type="submit" value="Save changes"></p>
        </form>
        {% endblock %}
        ```
    - Tes
        - Buat user baru, http://127.0.0.1:8000/account/register/
        - Edit account, http://127.0.0.1:8000/account/edit/
    - account/dashboard.html, replace with the new one
        ```
        <p>Welcome to your dashboard. You can <a href="{% url "edit" %}">edit
        your profile</a> or <a href="{% url "password_change" %}">change your
        password</a>.</p>
        ```
    
- Using a custom user model
    - bisa juga menggunakan custom user model, implementasi: https://docs.djangoproject.com/en/3.0/topics/auth/customizing/#substituting-a-custom-user-model.
    
- Using the messages framework
    - docs: https://docs.djangoproject.com/en/3.0/ref/contrib/messages/.
    - base.html
    - letakkan kode ini diantara div header dan content
        ```
        {% if messages %}
            <ul class="messages">
                {% for message in messages %}
                    <li class="{{ message.tags }}">
                        {{ message|safe }}
                        <a href="#" class="close">x</a>
                    </li>
                {% endfor %}
            </ul>
        {% endif %}
        ```
    - views.py --> edit()
        ```
        from django.contrib import messages

        @login_required
        def edit(request):
            if request.method == 'POST':
                # ...
                if user_form.is_valid() and profile_form.is_valid():
                    user_form.save()
                    profile_form.save()
                    messages.success(request, 'Profile updated ''successfully')
                else:
                    messages.error(request, 'Error updating your profile')
            else:
                user_form = UserEditForm(instance=request.user)
            # ...
        ```
    - Tes
        - http://127.0.0.1:8000/account/edit/
        - jika sukses akan muncul pesan

- Building a custom authentication backend
    - docs: https://docs.djangoproject.com/en/3.0/topics/auth/customizing/#otherauthentication-sources
    - Buat account/authentication.py
        ```
        from django.contrib.auth.models import User

        class EmailAuthBackend(object):
            
            #Authenticate using an e-mail address.
            def authenticate(self, request, username=None, password=None):
                try:
                    user = User.objects.get(email=username)
                    if user.check_password(password):
                        return user
                    return None
                except User.DoesNotExist:
                    return None
            def get_user(self, user_id):
                try:
                    return User.objects.get(pk=user_id)
                except User.DoesNotExist:
                    return None
        ```
    - settings.py
        ```
        AUTHENTICATION_BACKENDS = [
        'django.contrib.auth.backends.ModelBackend',
        'account.authentication.EmailAuthBackend',
        ]
        ```
    - Tes login menggunakan email
        - http://127.0.0.1:8000/account/login/
   

- Adding social authentication to your site
    - docs: https://python-social-auth.readthedocs.io/en/latest/backends/index.html#supported-backends.
    - pip install social-auth-app-django
    - register di settings.py --> 'social_django',
    - python manage.py migrate
    - core/urls.py
        ```
        path('social-auth/', include('social_django.urls', namespace='social')),
        ```
    - Ubah host menjadi dummy domain
        - C:\Windows\System32\Drivers\etc\hosts
        - 127.0.0.1  aris.com
        - settings.py --> ALLOWED_HOSTS
            ```
            ALLOWED_HOSTS = ['aris.com', 'localhost', '127.0.0.1']
            ```
        - Tes http://aris.com:8000/account/login/

- Running the development server through HTTPS
    - pip install django-extensions
    - settings.py --> INSTALLED_APPS --> 'django_extensions',
    - pip install werkzeug
    - pip install pyOpenSSL
    - python manage.py runserver_plus --cert-file cert.crt
    - https://mysite.com:8000/account/login/ --> menggunakan https, maka akan muncul peringatan untrusted image


- Authentication using Facebook
    - tutorial video: https://www.youtube.com/watch?v=oAWUyg_PPLk
    - settings.py --> AUTHENTICATION_BACKENDS
        ```
        'social_core.backends.facebook.FacebookOAuth2',
        ```
    - https://developers.facebook.com/apps/
    - settings.py
        ```
        SOCIAL_AUTH_FACEBOOK_KEY = 'XXX' # Facebook App ID
        SOCIAL_AUTH_FACEBOOK_SECRET = 'XXX' # Facebook App Secret
        SOCIAL_AUTH_FACEBOOK_SCOPE = ['email']
        ```
    - masukkan http://mysite.com:8000/social-auth/complete/facebook/ pada OAuth Redirect URIs
    - account/registration/login.html
        - letakkan dibawah content
            ```
            <div class="social">
            <ul>
            <li class="facebook">
            <a href="{% url "social:begin" "facebook" %}">Sign in with
            Facebook</a>
            </li>
            </ul>
            </div>
            ```
    - buka https://mysite.com:8000/account/login/, kini bisa login menggunakan fb

- Authentication using Twitter
    - skip, butuh review dulu

- Authentication using Google
    - Tutorial video: https://www.youtube.com/watch?v=kj9llVn5vJI&t=272s
    - https://developers.google.com/identity/protocols/OAuth2
    
    - settings.py --> AUTHENTICATION_BACKENDS
        ```
        'social_core.backends.google.GoogleOAuth2',
        ```
    - https://console.developers.google.com/apis/credentials
        - Authorised redirect URIs: Add https://aris.com:8000/social-auth/complete/google-oauth2/
    - settings.py
        ```
        SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = 'XXX' # Google Consumer Key
        SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = 'XXX' # Google Consumer Secret
        ```
    - registration/login.html
        ```
        <li class="google">
        <a href="{% url "social:begin" "google-oauth2" %}">Login with
        Google</a>
        </li>
        ```
    - https://mysite.com:8000/account/login/
    
<a name="B"></a>
## Chapter 5: Sharing Content on Your Website
- Creating an image bookmarking website
- django-admin startapp images
### Building the image model 150
Creating many-to-many relationships 152
Registering the image model in the administration site 153
Posting content from other websites 153
Cleaning form fields 154
Overriding the save() method of a ModelForm 155
Building a bookmarklet with jQuery 160
Creating a detail view for images 168
Creating image thumbnails using easy-thumbnails 170
Adding AJAX actions with jQuery 172
Loading jQuery 173
Cross-site request forgery in AJAX requests 174
Performing AJAX requests with jQuery 176
Creating custom decorators for your views 179
Adding AJAX pagination to your list views 181
Summary

<a name="B"></a>
## Chapter 6: Tracking User Actions 187
Building a follow system 187
Creating many-to-many relationships with an intermediary model 188
Creating list and detail views for user profiles 191
Building an AJAX view to follow users 196
Building a generic activity stream application 198
Using the contenttypes framework 200
Adding generic relations to your models 201
Avoiding duplicate actions in the activity stream 204
Adding user actions to the activity stream 205
Displaying the activity stream 206
Optimizing QuerySets that involve related objects 207
Using select_related() 207
Using prefetch_related() 208
Creating templates for actions 208
Using signals for denormalizing counts 210
Working with signals 211
Application configuration classes 213
Using Redis for storing item views 215
Installing Redis 215
Using Redis with Python 217
Storing item views in Redis 218
Storing a ranking in Redis 220
Next steps with Redis 223
Summary
