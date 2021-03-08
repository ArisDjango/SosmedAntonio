# Daftar isi - Bookmarks sosmed

- [ A. Chapter 4: Building a Social Website ](#A)
    - [ 1. Social website project ](#A1)
    - [ 2. Django authentication framework ](#A2)
        - [ 2.1. login views ](#A21)
        - [ 2.2. Django authentication views ](#A22)
        - [ 2.3. Login dan logout views ](#A23)
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
        - [ 4.1. Installing Redis](#C41)
        - [ 4.2. Using Redis with Python](#C42)
        - [ 4.3. Storing item views in Redis](#C43)
        - [ 4.4. Storing a ranking in Redis](#C44)
        - [ 4.5. Next steps with Redis](#C45)


<a name="A"></a>
## A. Chapter 4: Building a Social Website
<a name="A1"></a>
### A.1. Instalasi Django dan Struktur App
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
- model dari `account` apps
    - model.py
    - python manage.py makemigrations account
    - python manage.py migrate


<a name="A2"></a>
### A.2. Menggunakan Django authentication framework
    • AuthenticationMiddleware: Associates users with requests using sessions
    • SessionMiddleware: Handles the current session across requests
    The authentication framework also includes the following models:
        • User: A user model with basic fields; the main fields of this model are username, password, email, first_name, last_name, and is_active
        • Group: A group model to categorize users
        • Permission: Flags for users or groups to perform certain actions
<a name="A21"></a>
- A.2.1. login view ===========================
    - Tujuan:
        - Menggunakan django authentication framework untuk system login
        - Membuat view login yang menghandle:
            - data user/pass dari post user
            - otentikasi user terhadap data di dbase
            - cek apakah user aktif
            - Mengijinkan user masuk web dan memulai authentication session
        - login sementara menggunakan akun admin, Belum membahas registrasi user, itu akan dibahas di bab next

    - account/forms.py

        ```python

            from django import forms

            class LoginForm(forms.Form):
                username = forms.CharField()
                password = forms.CharField(widget=forms.PasswordInput)
        ```
    - account/views.py

        ```python

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

        ```python

        from django.urls import path
        from . import views

        urlpatterns = [
        # post views
            path('login/', views.user_login, name='login'),
        ]
        ```
    - core/urls.py

        ```python

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

            ```html

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
        - edit account/login.html

            ```html

            {% extends "base.html" %}
            {% block title %}Log-in{% endblock %}

            {% block content %}

                <h1>Log-in</h1>
                    <p>Please, use the following form to log-in:</p>
                <form method="post">
                    {{ form.as_p }}
                    {% csrf_token %}
                    <p><input type="submit" value="Log in"></p>
                </form>
            {% endblock %}
            ```
    - 127.0.0.1:8000/admin/
    - 127.0.0.1:8000/account/login
    - maka akan muncul halaman login

<a name="A22"></a>
- A.2.2. Using Django authentication views
    - docs : https://docs.djangoproject.com/en/3.0/topics/auth/default/#allauthentication-
    - otentifikasi bawaan django dihandle `django.contrib.auth.views`:
        - Login and Logout
            • LoginView: menghandle form login user
            • LogoutView: Logout user

        - views untuk menghandle perubahan password :
            • PasswordChangeView: menghandel form perubahan password user
            • PasswordChangeDoneView: menghandle view ketika perubahan password berhasil redirect ke ...
        - views untuk menghandle reset password:
            • PasswordResetView: sistem reset password yang menggenerate one-time-use link dengan token dan dikirim ke email user
            • PasswordResetDoneView: pesan ke user bahwa link reset sudah dikirim ke email.
            • PasswordResetConfirmView: user mengatur password baru.
            • PasswordResetCompleteView: pesan ke user bahwa reset password berhasil, dan redirect ke home.

<a name="A23"></a>        
- A.2.3. Login and logout views
    - Edit account/urls.py

        ```python

        from django.contrib.auth import views as auth_views
            ...
            # path('login/', views.user_login, name='login'),
            path('login/', auth_views.LoginView.as_view(), name='login'),
            path('logout/', auth_views.LogoutView.as_view(), name='logout'),

        ```
    - Buat templates/registration/login.html

        ```html

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

        ```html

        {% extends "base.html" %}
        {% block title %}Logged out{% endblock %}

        {% block content %}
        
        <h1>Logged out</h1>
        <p>
            Anda telah berhasil logged out.
            You can <a href="{% url "login" %}">log-in again</a>.
        </p>

        {% endblock %}

        ```
    - Edit account/views.py

        ```python

        from django.contrib.auth.decorators import login_required

        @login_required
        def dashboard(request):
            return render(request,'account/dashboard.html',{'section': 'dashboard'})

        ```
    - Buat templates/account/dashboard.html

        ```html

        {% extends "base.html" %}
        {% block title %}Dashboard{% endblock %}
        {% block content %}

        <h1>Dashboard</h1>
        <p>Welcome to your dashboard.</p>
        {% endblock %}

        ```
    - Edit account/urls.py

        ```python

        path('', views.dashboard, name='dashboard'),

        ```
    - Edit core/settings.py

        ```python

        LOGIN_REDIRECT_URL = 'dashboard'
        LOGIN_URL = 'login'
        LOGOUT_URL = 'logout'
        ```
        ```
        Note:
        • LOGIN_REDIRECT_URL: redirect URL setelah user berhasil login (jika tidak ada next parameter lain)
        • LOGIN_URL: URL untuk user log in (ex:, views menggunakan login_required decorator)
        • LOGOUT_URL: URL untuk user log out
        ```
    - Edit templates/base.html

        ```html

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

<a name="A24"></a>
- A.2.4. Changing password views
    - Edit account/urls.py

        ```python

            # change password urls
            path('password_change/', auth_views.PasswordChangeView.as_view(), name='password_change'),
            path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(), name='password_change_done'),
        ```
    - Buat templates/registration/password_change_form.html

        ```html

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

        ```html

        {% extends "base.html" %}
        {% block title %}Password changed{% endblock %}

        {% block content %}
        <h1>Password changed</h1>
        <p>Your password has been successfully changed.</p>
        {% endblock %}
        ```
    - http://127.0.0.1:8000/account/password_change/

<a name="A25"></a>
- A.2.5. Resetting password views
    - Edit account/urls.py

        ```python

        # reset password urls
        path('password_reset/', auth_views.PasswordResetView.as_view(), name='password_reset'),
        path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
        path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
        path('reset/done/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
        ```
    - Buat file baru templates/registration/password_reset_form.html

        ```html

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

        ```html

        Someone asked for password reset for email {{ email }}. Follow the link below:
        {{ protocol }}://{{ domain }}{% url "password_reset_confirm" uidb64=uid token=token %}
        Your username, in case you've forgotten: {{ user.get_username }}

        ```
    - Buat file baru templates/registration/password_reset_confirm.html

        ```html

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

        ```html

        {% extends "base.html" %}
        {% block title %}Password reset{% endblock %}
        {% block content %}

        <h1>Password set</h1>
        <p>Your password has been set. You can
        <a href="{% url "login" %}">log in now</a></p>

        {% endblock %}

        ```
    - Edit registration/login.html

        ```html

        <p><a href="{% url "password_reset" %}">Forgotten your password?</a></p>

        ```
    - pada core/settings.py, tambahkan setting email

        ```python

        EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

        ```
    - http://127.0.0.1:8000/account/login/, lalu coba 'forgotten your password'
    - Setelah fungsi reset berhasil, bisa mengganti semua auth.url pada account/urls menggunakan include (sama saja)
    - doc auth.url: https://github.com/django/django/blob/stable/3.0.x/django/contrib/auth/urls.py.

        ```python

        from django.urls import path, include
        # ...
        urlpatterns = [
        # ...
        path('', include('django.contrib.auth.urls')),
        ]
        ```
<a name="A3"></a>
### A.3. User registration and user profiles
- Saat ini user yang telah terdaftar di db(didaftarkan admin), bisa login, logout, merubah password, reset password. 
- sekarang saatnya membuat anonymous visitor agar bisa membuat akun user.
<a name="A31"></a>

- A.3.1. User registration
    - Edit account/forms.py
        ```python
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
        ```
        Note:
        - Menggunakan model form bawaan django (default field: username, first_name, email)
        - Validasi username menggunakan parameter bawaaan model.form. akan error jika menggunakan username yang sama, karena param field username defaultnya unique=True
        - ada 2 field tambahan, password & password2
        - clean_password2() --> validasi password terhadap password2, harus sama
        - cd = membersihkan field dari data input lama
        ```
    - Edit account/Views.py

        ```python

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
        ```
        Note:
        - import UserRegistrationForm() dari forms.py
        - merequest post dari form tsb yg tampil di-->register.html
        - is_valid() --> jika form.py tervalidasi, lanjut
        - .set_password() --> hashing format password
        - .save() --> Menyimpan user
        - views digunakan oleh --> template/account/register.html
        ```
    - Edit account/urls.py
        ```python
        path('register/', views.register, name='register'),
        ```
    - Buat template/account/register.html

        ```html
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
        ```
        Note:
        - user_form = dari views.register
        - as_p = digunakan sebagai post, ini yg akan diolah views
        ```
    - http://127.0.0.1:8000/account/register/
    - Edit registration/login.html
        ```html
        <p>Please, use the following form to log-in. If you don't have an account <a href="{% url "register" % ">register here</a></p>
        ```
        ```
        Note:
        - % url "register" % = path('register/', views.register, name='register'),
        ```
<a name="A32"></a>
- A.3.2. Extending the user model
    - Edit account/models.py
        - docs: https://docs.djangoproject.com/en/3.0/topics/auth/customizing/#django.contrib.auth.get_user_model

        ```python

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

        ```python

        MEDIA_URL = '/media/'
        MEDIA_ROOT = os.path.join(BASE_DIR, 'media/')
        ```
    - core/urls.py

        ```python

        from django.conf import settings
        from django.conf.urls.static import static

        urlpatterns ...

        if settings.DEBUG: urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
        ```
    - python manage.py makemigrations
    - python manage.py migrate

    - admin.py

        ```python

        from django.contrib import admin
        from .models import Profile

        @admin.register(Profile)
        class ProfileAdmin(admin.ModelAdmin):
            list_display = ['user', 'date_of_birth', 'photo']
        ```
        - http://127.0.0.1:8000/admin/

    - account/forms.py

        ```python

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

        ```python

        from .models import Profile

        register()
            ...
            new_user.save()
            
            # Create the user profile
            Profile.objects.create(user=new_user)
        ```
    - views.py

        ```python

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

        ```python

        path('edit/', views.edit, name='edit'),
        ```
    - Buat templates/account/edit.html

        ```html

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

        ```html

        <p>Welcome to your dashboard. You can <a href="{% url "edit" %}">edit
        your profile</a> or <a href="{% url "password_change" %}">change your
        password</a>.</p>
        ```
<a name="A33"></a>    
- A.3.3. Using a custom user model
    - bisa juga menggunakan custom user model, implementasi: https://docs.djangoproject.com/en/3.0/topics/auth/customizing/#substituting-a-custom-user-model.

<a name="A34"></a>
- A.3.4. Using the messages framework
    - docs: https://docs.djangoproject.com/en/3.0/ref/contrib/messages/.
    - base.html
    - letakkan kode ini diantara div header dan content

        ```html

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

        ```python

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

<a name="A4"></a>
### A.4. Building a custom authentication backend
- docs: https://docs.djangoproject.com/en/3.0/topics/auth/customizing/#otherauthentication-sources

    - Buat account/authentication.py

        ```python

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

        ```python

        AUTHENTICATION_BACKENDS = [
        'django.contrib.auth.backends.ModelBackend',
        'account.authentication.EmailAuthBackend',
        ]
        ```
    - Tes login menggunakan email
        - http://127.0.0.1:8000/account/login/
   
<a name="A5"></a>
### A.5. Adding social authentication to your site
- docs: https://python-social-auth.readthedocs.io/en/latest/backends/index.html#supported-backends.
    - pip install social-auth-app-django
    - register di settings.py --> 'social_django',
    - python manage.py migrate
    - core/urls.py

        ```python

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
<a name="A51"></a>
- A.5.1. Running the development server through HTTPS
    - pip install django-extensions
    - settings.py --> INSTALLED_APPS --> 'django_extensions',
    - pip install werkzeug
    - pip install pyOpenSSL
    - python manage.py runserver_plus --cert-file cert.crt
    - https://mysite.com:8000/account/login/ --> menggunakan https, maka akan muncul peringatan untrusted image

<a name="A52"></a>
- A.5.2. Authentication using Facebook
    - tutorial video: https://www.youtube.com/watch?v=oAWUyg_PPLk
    - settings.py --> AUTHENTICATION_BACKENDS

            ```python

            'social_core.backends.facebook.FacebookOAuth2',

            ```
    - https://developers.facebook.com/apps/
    - settings.py

            ```python

            SOCIAL_AUTH_FACEBOOK_KEY = 'XXX' # Facebook App ID
            SOCIAL_AUTH_FACEBOOK_SECRET = 'XXX' # Facebook App Secret
            SOCIAL_AUTH_FACEBOOK_SCOPE = ['email']
            ```
    - masukkan http://mysite.com:8000/social-auth/complete/facebook/ pada OAuth Redirect URIs
    - account/registration/login.html
        - letakkan dibawah content

            ```html

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
<a name="A53"></a>
    - A.5.3. Authentication using Twitter
        - skip, butuh review dulu
<a name="A54"></a>
    - Authentication using Google
        - Tutorial video: https://www.youtube.com/watch?v=kj9llVn5vJI&t=272s
        - https://developers.google.com/identity/protocols/OAuth2
        
        - settings.py --> AUTHENTICATION_BACKENDS

            ```python

            'social_core.backends.google.GoogleOAuth2',
            ```
        - https://console.developers.google.com/apis/credentials
            - Authorised redirect URIs: Add https://aris.com:8000/social-auth/complete/google-oauth2/
        - settings.py

            ```python

            SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = 'XXX' # Google Consumer Key
            SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = 'XXX' # Google Consumer Secret
            ```
        - registration/login.html

            ```html

            <li class="google">
            <a href="{% url "social:begin" "google-oauth2" %}">Login with
            Google</a>
            </li>
            ```
        - https://mysite.com:8000/account/login/
    
<a name="B"></a>
## Chapter 5: Sharing Content on Your Website
- Akan membahas:
    • Membuat relasi databse many-to-many 
    • Custom behavior untuk forms
    • Menggunakan jQuery dengan Django
    • Membuat jQuery bookmarklet
    • image thumbnails menggunakan easy-thumbnails
    • Implementasi AJAX views dan mengintegrasikan dengan jQuery
    • Membuat custom decorators untuk views
    • menggunakan AJAX pagination
<a name="B1"></a>
### Creating an image bookmarking website
- Tujuan:
    1. Membuat model untuk menyimpan image beserta informasinya
    2. Membuat form dan view untuk menghandle image upload
    3. Membuat sistem untuk users agar bisa melakukan post images yang didapatkan/di bookmarks dari website lain
- Membuat app baru didalam bookmarks directory --> images
    - `django-admin startapp images `
- registrasi di settings.py
    ```
    INSTALLED_APPS = [
    # ...
    'images.apps.ImagesConfig',
    ]
    ```

<a name="B11"></a>
- Building the image model
    - Edit images/models.py

        ```py

        from django.db import models
        from django.conf import settings

        class Image(models.Model):
            user = models.ForeignKey(settings.AUTH_USER_MODEL,related_name='images_created',on_delete=models.CASCADE)
            title = models.CharField(max_length=200)
            slug = models.SlugField(max_length=200,blank=True)
            url = models.URLField()
            image = models.ImageField(upload_to='images/%Y/%m/%d/')
            description = models.TextField(blank=True)
            created = models.DateField(auto_now_add=True,db_index=True)

        ```
        ```
        - Note:
            - slug: label agar URL terlihat SEO-friendly.
            - url: original URL untuk image.

        - Database index meningkatkan performa query. pertimbangkan menggunakan db_index=True untuk fields dimana query menggunakan filter(), exclude(), atau order_by().ForeignKey fields atau fields dengan unique=True mengindikasikan pembuatan index.

        - Juga bisa menggunakan Meta.index_together atau Meta.indexes untuk membuat index pada multiple fields.

        - Docs database index: https://docs.djangoproject.com/en/3.0/ref/models/options/#django.db.models.Options.indexes.

        ```
    - menggunakan slugify()
        - Fungsi:
            - Menciptakan slug, agar url lebih enak dibaca
            - slug tercipta otomatis dari input title
        - masih pada model, tambahkan:

        ```python

            from django.utils.text import slugify

            class Image(models.Model):
                # ...
                def save(self, *args, **kwargs):
                if not self.slug:
                    self.slug = slugify(self.title)
                super().save(*args, **kwargs)
        ```

<a name="B12"></a>
- Creating many-to-many relationships
    - Tujuan:
        - Docs : https://docs.djangoproject.com/en/3.0/topics/db/examples/many_to_many/.
        - Membuat field baru pada model untuk menyimpan users yang me-like image.
        - Membutuhkan relasi many-to-many karena user bisa me-like multiple images dan setiap image bisa di like oleh multiple user
    - edit models.py

        ```python

        users_like = models.ManyToManyField(settings.AUTH_USER_MODEL,
                                            related_name='images_liked',
                                            blank=True)
        ```
        ```
        Note:
        - ManyToManyField --> menciptakan *join table* mengunakan primary keys dari kedua models.

        - ManyToManyField bisa didefiniskan pada salah satu field models.

        - related_name attribute memberikan nama relationship. - ManyToManyField fields menyediakan many-to-many manager yang memungkinkan mengambil objects, seperti image.users_like.all(), atau dari user object, seperti user.images_liked.all().
        ```
    - python manage.py makemigrations images
    - python manage.py migrate images
<a name="B13"></a>
- Registering the image model in the administration site
    - Edit admin.py

        ```python
        
        from django.contrib import admin
        from .models import Image
        @admin.register(Image)
        class ImageAdmin(admin.ModelAdmin):
            list_display = ['title', 'slug', 'image', 'created']
            list_filter = ['created']
        ```
    - Run server menggunakan https
        ```
        python manage.py runserver_plus --cert-file cert.crt
        ```
    - https://127.0.0.1:8000/admin/

<a name="B2"></a>
### Posting content from other websites
- Tujuan:
    - Bookmark/grab image dari website lain dan otomatis membuat 'image object' baru di database
    - User menyediakan URL image, title, description(optional)
- Membuat Form untuk submit image
    - Buat images/forms.py

        ```python

        from django import forms
        from .models import Image

        class ImageCreateForm(forms.ModelForm):
            class Meta:
                model = Image
                fields = ('title', 'url', 'description')
                widgets = {
                    'url': forms.HiddenInput,
                }
        ```
        ```
        Note:
        - Dari model ditransformasi menjadi ModelForm
        - untuk fields 'url' nantinya otomatis didapatkan ketika proses bookmarks image (menggunakan javascript), dan akan26 mengambil url sebagai parameternya
        - pada html, form 'url' di sembunyikan menggunakan HiddenInput
        ```


<a name="B21"></a>
- B.2.1. Cleaning form fields
    - Tujuan :
        - Memastikan url image yang diambil adalah url berakhiran 'jpeg'
    - Tambahkan pada ImageCreateForm()

        ```python
            def clean_url(self):
                url = self.cleaned_data['url']
                valid_extensions = ['jpg', 'jpeg']
                extension = url.rsplit('.', 1)[1].lower()
                if extension not in valid_extensions:
                    raise forms.ValidationError('The given URL does not ' \
                    'match valid image extensions.')
                return url
        ```
        ```
        Note:
            cleaned_data perlu dipelajari
        ```
<a name="B22"></a>
- B.2.2. Overriding the save() method of a ModelForm
    - Tujuan:
        - pada model form, menggunakan save() untuk menyimpan  model instance ke database dan me return object.
        - selanjutnya menerima commit, jika false, maka save() akan mereturn model instance namun tidak disimpan di database
        - overide save() pada form agar bisa mengambil image dan menyimpannya

    - Pada forms.py:

    ```python
    from urllib import request
    from django.core.files.base import ContentFile
    from django.utils.text import slugify

    def save(self, force_insert=False, force_update=False, commit=True):
        image = super().save(commit=False)
        image_url = self.cleaned_data['url']
        name = slugify(image.title)
        extension = image_url.rsplit('.', 1)[1].lower()
        image_name = f'{name}.{extension}'
        # download image from the given URL
        response = request.urlopen(image_url)
        image.image.save(image_name,
                        ContentFile(response.read()),
                        save=False)
        if commit:
            image.save()
        return image
    ```
    ```
    Kita sedang mengoveride save() method, dengan parameters yang dibutuhkan oleh ModelForm.

    Penjelasan:
    1. membuat image instance baru dengan cara memanggil save() method pada form dengan parameter commit=False.
    
    2. Mendapatkan URL dari cleaned_data dictionary pada form.

    3. Mendapatkan nama image dengan mengkombinasikan  image title slug dengan original file extension.

    4. Menggunakan Python urllib untuk mendownload image lalu memanggil save() method pada image field, meneruskannya ke ContentFile object yang terinstansiasi dengan file content yang telah terdownload. dengan cara ini, kita menyimpan file ke media directory project. kita meneruskan save=False parameter untuk menghindari menyimpan object kle database

    5. untuk mempertahankan behavior yang sama seperti save() method yang kita override, kita menyimpan form ke database hanya jika commit parameter = True.

    dalam menggunakan urllib untuk mengambil images dari URLs dengan HTTPS, harus menginstall Certifi Python package. Certifi adalah koleksi dari root certificates untuk memvalidasi SSL/TLS certificates.

    pip install --upgrade certifi

    ```
    - Edit Images/Views.py

    ```python
    from django.shortcuts import render, redirect
    from django.contrib.auth.decorators import login_required
    from django.contrib import messages
    from .forms import ImageCreateForm

    @login_required
    def image_create(request):
        if request.method == 'POST':
        # form is sent
            form = ImageCreateForm(data=request.POST)
            if form.is_valid():
                # form data is valid
                cd = form.cleaned_data
                new_item = form.save(commit=False)
                # assign current user to the item
                new_item.user = request.user
                new_item.save()
                messages.success(request, 'Image added successfully')
                # redirect to new created item detail view
                return redirect(new_item.get_absolute_url())
        else:
            # build form with data provided by the bookmarklet via GET
            form = ImageCreateForm(data=request.GET)
        return render(request,'images/image/create.html',{'section': 'images','form': form})
    ```
    ```
    Note:

    Menggunakan decorator login_required untuk image_create view untuk menghindari access dari users yang tidak terotentifikasi.

    1. mendapatkan data via GET untuk membuat instance pada form. data yang diambil adalah url dan title pada image form yang diambil dari external website dan akan dilakukan via GET dengan JavaScript tool yang nanti akan kita buat. saat ini asumsikan saja ada.

    2. jika form tersubmit, akan dicek validitasnya. jika form data valid, maka akan membuat Image instance baru.
    Untuk mencegah object langsung tersimpan di db, maka save() pada form menggunakan atribut 'commit=False'

    3. mengunakan user aktif ke image object baru. dengan begini kita akan tahu siapa yang upload image.

    4. menyimpan image object ke database.

    5. Terakhir, menampilkan pesan sukses menggunakan django messaging framework dan redirect user ke URL pada image. saat ini kita belum membuat get_absolute_url
    ```

    - Membuat image/urls.py

    ```python
    
    from django.urls import path
    from . import views

    app_name = 'images'

    urlpatterns = [
        path('create/', views.image_create, name='create'),
    ]
    ```

    - Edit core/urls.py

        ```python

        urlpatterns = [
        path('admin/', admin.site.urls),
        path('account/', include('account.urls')),
        path('social-auth/', include('social_django.urls', namespace='social')),
        path('images/', include('images.urls', namespace='images')),
        ]

        ```
        ```
        Note: Menambahkan path images
        ```
    - Templates
        - Buat templates/images/image/create.html

        ```html

        {% extends "base.html" %}
        {% block title %}Bookmark an image{% endblock %}
        {% block content %}

        <h1>Bookmark an image</h1>
            <img src="{{ request.GET.url }}" class="image-preview">
        <form method="post">
            {{ form.as_p }}
            {% csrf_token %}
            <input type="submit" value="Bookmark it!">
        </form>

        {% endblock %}
        ```
    - `python manage.py runserver_plus --cert-file cert.crt`
    - sebagai contoh untuk mengetes fungsional, coba akses `https://127.0.0.1:8000/images/create/?title=%20Django%20and%20Duke&url=https://upload.wikimedia.org/wikipedia/commons/8/85/Django_Reinhardt_and_Duke_Ellington_%28Gottlieb%29.jpg.`
    - Buka https://127.0.0.1:8000/admin/images/image/ , untuk memastikan ada image baru yang terimpan
    

<a name="B23"></a>
- B.2.3. Building a bookmarklet with jQuery
    - Tujuan:
        - A bookmarklet is a bookmark stored in a web browser that contains JavaScript code to extend the browser's functionality. When you click on the bookmark, the JavaScript code is executed on the website being displayed in the browser. This is very useful for building tools that interact with other websites.
        - Let's create a bookmarklet in a similar way for your website, using jQuery. official website: https://jquery.com/.
        - Cara pengunaan bookmarklet
            - drag button link bookmark ke browser tab
            - Kunjungi web yang mengandung image dan klik pada bookmarklet di tab browser tadi
    - Buat images/templates/bookmarklet_launcher.js

        ```js

        (function(){
        if (window.myBookmarklet !== undefined){
        myBookmarklet();
        }
        else {
        document.body.appendChild(document.createElement('script')).
        src='https://127.0.0.1:8000/static/js/bookmarklet.js?r='+Math.
        floor(Math.random()*99999999999999999999);
        }
        })();
        
        ```
    - Edit account/dashboard.html

        ```html

        {% extends "base.html" %}
        {% block title %}Dashboard{% endblock %}
        {% block content %}

        <h1>Dashboard</h1>

        {% with total_images_created=request.user.images_created.count%}
            <p>Welcome to your dashboard. You have bookmarked {{ total_images_created }} image{{ total_images_created|pluralize }}.</p>
        {% endwith %}

        <p>Drag the following button to your bookmarks toolbar to bookmark images from other websites → <a href="javascript:{% include "bookmarklet_launcher.js" %}" class="button">Bookmark it</a></p>

        <p>You can also <a href="{% url "edit" %}">edit your profile</a>
        or <a href="{% url "password_change" %}">change your password</a>.</p>

        {% endblock %}
        ```
        ```
        Note:
        
            - The dashboard now displays the total number of images bookmarked by the user.You use the {% with %} template tag to set a variable with the total number of images bookmarked by the current user.

            -  You include a link with an href attribute that contains the bookmarklet launcher script. You will include this JavaScript code from the bookmarklet_launcher.js template.
        ```
    - https://127.0.0.1:8000/account/

    - Buat file static untuk images
        - images/static/css/bookmarklet.css
        - images/static/js/bookmarklet.js

        ```js
        (function(){
            var jquery_version = '3.4.1';
            var site_url = 'https://127.0.0.1:8000/';
            var static_url = site_url + 'static/';
            var min_width = 100;
            var min_height = 100;

            function bookmarklet(msg) {
                // Here goes our bookmarklet code
                    // load CSS
                var css = jQuery('<link>');
                css.attr({
                    rel: 'stylesheet',
                    type: 'text/css',
                    href: static_url + 'css/bookmarklet.css?r=' + Math.floor(Math.random()*99999999999999999999)
                });
                jQuery('head').append(css);

                // load HTML
                box_html = '<div id="bookmarklet"><a href="#" id="close">&times;</a><h1>Select an image to bookmark:</h1><div class="images"></div></div>';
                jQuery('body').append(box_html);

                // close event
                jQuery('#bookmarklet #close').click(function(){
                jQuery('#bookmarklet').remove();
                });
                // find images and display them
                jQuery.each(jQuery('img[src$="jpg"]'), function(index, image) {
                    if (jQuery(image).width() >= min_width && jQuery(image).height()
                >= min_height)
                {
                    image_url = jQuery(image).attr('src');
                    jQuery('#bookmarklet .images').append('<a href="#"><img src="'+
                    image_url +'" /></a>');
                }
                });

                // when an image is selected open URL with it
                jQuery('#bookmarklet .images a').click(function(e){
                selected_image = jQuery(this).children('img').attr('src');
                // hide bookmarklet
                jQuery('#bookmarklet').hide();
                // open new window to submit the image
                window.open(site_url +'images/create/?url='
                            + encodeURIComponent(selected_image)
                            + '&title='
                            + encodeURIComponent(jQuery('title').text()),
                            '_blank');
                });

            };


                // Check if jQuery is loaded
                if(typeof window.jQuery != 'undefined') {
                    bookmarklet();
                } else {
                    // Check for conflicts
                    var conflict = typeof window.$ != 'undefined';
                    // Create the script and point to Google API
                    var script = document.createElement('script');
                    script.src = '//ajax.googleapis.com/ajax/libs/jquery/' +
                    jquery_version + '/jquery.min.js';
                    // Add the script to the 'head' for processing
                    document.head.appendChild(script);
                    // Create a way to wait until script loading
                    var attempts = 15;
                    (function(){
                    // Check again if jQuery is undefined
                    if(typeof window.jQuery == 'undefined') {
                        if(--attempts > 0) {
                        // Calls himself in a few milliseconds
                        window.setTimeout(arguments.callee, 250)
                        } else {
                        // Too much attempts to load, send error
                        alert('An error occurred while loading jQuery')
                        }
                    } else {
                        bookmarklet();
                    }
                    })();
                }
                })()
        ```
        ```
        Note:
            - You add an event that removes your HTML from the document when the user clicks on the close link of your HTML block.

            - You use the #bookmarklet #close selector to find the HTML element with an ID named close, which has a parent element with an ID named bookmarklet. jQuery selectors allow you to find HTML elements. A jQuery selector returns all elements found by the given CSS selector.
            
            - You can find a list of jQuery selectors at https:// api.jquery.com/category/selectors/.
        ```
    - `python manage.py runserver_plus --cert-file cert.crt`

<a name="B3"></a>
### B.3. Creating a detail view for images
- Membuat view untuk tampilan detail images
- images/views.py

    ```python
    from django.shortcuts import get_object_or_404
    from .models import Image

    def image_detail(request, id, slug):
        image = get_object_or_404(Image, id=id, slug=slug)
        return render(request,
        'images/image/detail.html',
        {'section': 'images',
        'image': image})
        
    ```
- images/urls.py

    ```python
    path('detail/<int:id>/<slug:slug>/',views.image_detail,name='detail'),
    ```
- images/models.py
    ```python
    from django.urls import reverse

    class Image(models.Model):
        # ...
        def get_absolute_url(self):
            return reverse('images:detail', args=[self.id, self.slug])
    ```
    ```
    Note:
    - add get_absolute_url()

    - Remember that the common pattern for providing canonical URLs for objects is to define a get_absolute_url() method in the model.
    ```
- Buat Templates/images/image/detail.html

    ```html
    {% extends "base.html" %}
    {% block title %}{{ image.title }}{% endblock %}

    {% block content %}

        <h1>{{ image.title }}</h1>
        <img src="{{ image.image.url }}" class="image-detail">
        {% with total_likes=image.users_like.count %}
        <div class="image-info">
            <div>
                <span class="count">    
                {{ total_likes }} like{{ total_likes|pluralize }}
                </span>
            </div>
            {{ image.description|linebreaks }}
        </div>
        <div class="image-likes">
            {% for user in image.users_like.all %}
            <div>
                <img src="{{ user.profile.photo.url }}">
                <p>{{ user.first_name }}</p>
            </div>
            {% empty %}
                Nobody likes this image yet.
            {% endfor %}
        </div>

        {% endwith %}
    {% endblock %}
    ```
    ```
    Note:
    - This is the template to display the detail view of a bookmarked image.
    - You make use of the {% with %} tag to store the result of the QuerySet, counting all user likes in a new variable called total_likes. By doing so, you avoid evaluating the same QuerySet twice.
    - You also include the image description and iterate over image. users_like.all to display all the users who like this image.

    "Whenever you need to repeat a query in your template, use the {% with %} template tag to avoid additional database queries."
    ```
- Next, bookmark a new image using the bookmarklet. You will be redirected to the image detail page after you post the image. The page will include a success message.
<a name="B4"></a>
### Creating image thumbnails using easy-thumbnails
- Tujuan:
    - You are displaying the original image on the detail page, but dimensions fordifferent images may vary considerably.
    - Also, the original files for some images may be huge, and loading them might take too long.
    - The best way to display optimized images in a uniform way is to generate thumbnails. Let's use a Django application called easy-thumbnails for this purpose.

- `pip install easy-thumbnails==2.7`

- pada settings.py

    ```conf
    INSTALLED_APPS = [
    # ...
    'easy_thumbnails',
    ]
    ```
- `python manage.py migrate`
- Edit images/image/detail.html
    ```html
    dari
    <img src="{{ image.image.url }}" class="image-detail">

    menjadi

    {% load thumbnail %}
    <a href="{{ image.image.url }}">
        <img src="{% thumbnail image.image 300x0 %}" class="image-detail">
    </a>
    ```
    ```
    Note:
    - The thumbnail is stored in the same directory of the original file. The location is defined by the MEDIA_ROOT setting and the upload_to attribute of the image field of the Image model.

    - To set the highest JPEG quality, you can use the value 100 like this {% thumbnail image.image 300x0 quality=100 %}.

    - The easy-thumbnails application offers several options to customize your thumbnails, including cropping algorithms and different effects that can be applied.

    - If you have any difficulty generating thumbnails, you can add THUMBNAIL_DEBUG = True to the settings.py file in order to obtain debug information.

    - You can read the full documentation of easy-thumbnails at https://easy-thumbnails.readthedocs.io/.
    ```

<a name="B5"></a>
### B.5. Adding AJAX actions with jQuery
- Tujuan:
    - LIKE / UNLIKE BUTTON
    - You are going to add a link to the image detail page to let users click on it in order to like an image. You will perform this action with an AJAX call to avoid reloading the whole page.
    - AJAX comes from Asynchronous JavaScript and XML, encompassing a group of techniques to make asynchronous HTTP requests.
    - It consists of sending and retrieving data from the server asynchronously, without reloading the whole page.
    - You can send or retrieve data in other formats, such as JSON, HTML, or plain text.
- images/views.py --> users to like/unlike images

    ```python
    from django.http import JsonResponse
    from django.views.decorators.http import require_POST

    @login_required
    @require_POST
    def image_like(request):
        image_id = request.POST.get('id')
        action = request.POST.get('action')
        if image_id and action:
            try:
                image = Image.objects.get(id=image_id)
                if action == 'like':
                    image.users_like.add(request.user)
                else:
                    image.users_like.remove(request.user)
                return JsonResponse({'status':'ok'})
            except:
                pass
        return JsonResponse({'status':'error'})
    ```
    ```
    Note:
    - The login_required decorator --> prevents users who are not logged in from accessing this view.

    - The require_POST decorator --> returns an HttpResponseNotAllowed object (status code 405) if the HTTP request is not done via POST. This way, you only allow POST requests for this view.
        " Django also provides a require_GET decorator --> to only allow GET requests and a require_http_methods decorator to which you can pass a list of allowed methods as an argument."

    - In this view, you use two POST parameters:
        • image_id: The ID of the image object on which the user is performing the action
        • action: The action that the user wants to perform, which you assume to be a string with the value like or unlike

    - You use the manager provided by Django for the users_like many-to-many field of the Image model in order to add or remove objects from the relationship using the add() or remove() methods.
        • add() --> passing an object that is already present in the related object set, does not duplicate it.
        • remove() --> passing an object that is not in the related object set does nothing.
        • Another useful method of many-to-many managers is clear(), which removes all objects from the related object set.

    - JsonResponse() --> class provided by Django, which returns an HTTP response with an application/json content type, converting the given object into a JSON output.
    ```
- Edit the images/urls.py
    ```
    path('like/', views.image_like, name='like'),
    ```
<a name="B51"></a>
- Loading jQuery
- Tujuan : 
    - You will need to add the AJAX functionality to your image detail template.
- Edit account/templates/base.html
    - include the following code before the closing `</body>` HTML tag:

    ```js
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
    
    <script>
        $(document).ready(function(){
            {% block domready %}
            {% endblock %}
        });
    </script>

    ```
    ```
    Note:
    - You load the jQuery framework from Google's CDN. You can also download jQuery from https://jquery.com/ and add it to the static directory of your application instead.

    - $(document).ready()
        - is a jQuery function that takes a handler that is executed when the Document Object Model (DOM) hierarchy has been fully constructed.

        - The DOM is created by the browser when a web page is loaded, and it is constructed as a tree of objects.

        - By including your code inside this function, you will make sure that all HTML elements that you are going to interact with are loaded in the DOM. Your code will only be executed once the DOM is ready.

    - Inside the document-ready handler function
        - you include a Django template block called domready, in which templates that extend the base template will be able to include specific JavaScript.

        - The Django template language is rendered on the server side, outputting the final HTML document, and JavaScript is executed on the client side.

        - In some cases, it is useful to generate JavaScript code dynamically using Django, to be able to use the results of QuerySets or server-side calculations to define variables in JavaScript.

        - The examples in this chapter include JavaScript code in Django templates. The preferred way to include JavaScript code is by loading .js files, which are served as static files, especially when they are large scripts.
    ```
<a name="B52"></a>
- B.5.2. Cross-site request forgery in AJAX requests
    - Tujuan:
        - Docs CSRF protection and AJAX : https://docs.djangoproject.com/en/3.0/ref/csrf/#ajax.
        - With CSRF protection active, Django checks for a CSRF token in all POST requests.
        - When you submit forms, you can use the {% csrf_token %} template tag to send the token along with the form.
        - However, it is a bit inconvenient for AJAX requests to pass the CSRF token as POST data with every POST request.
        - Therefore, Django allows you to set a custom X-CSRFToken header in your AJAX requests with the value of the CSRF token. This enables you to set up jQuery or any other JavaScript library to automatically set the X-CSRFToken header in every request.
        - In order to include the token in all requests, you need to take the following steps:
            1. Retrieve the CSRF token from the csrftoken cookie, which is set if CSRF protection is active
            2. Send the token in the AJAX request using the X-CSRFToken header
    - Edit base.html

        ```js

            <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/js-cookie@2.2.1/src/js.cookie.min.js"></script>
            <script>
            var csrftoken = Cookies.get('csrftoken');
            function csrfSafeMethod(method) {
                // these HTTP methods do not require CSRF protection
                return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
                    }
            $.ajaxSetup({
                    beforeSend: function(xhr, settings) {
                    if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
                        xhr.setRequestHeader("X-CSRFToken", csrftoken);
                        }
                    }
                });
            $(document).ready(function(){
                {% block domready %}
                {% endblock %}
            });
            </script>

        ```
        ```
        Note:
        1. You load the JS Cookie plugin from a public CDN so that you can easily interact with cookies. JS Cookie is a lightweight JavaScript API for handling cookies. You can learn more about it at https://github.com/js-cookie/js-cookie.

        2. You read the value of the csrftoken cookie with Cookies.get().

        3. You define the csrfSafeMethod() function to check whether an HTTP method is safe. Safe methods don't require CSRF protection—these are GET, HEAD, OPTIONS, and TRACE.

        4. You set up jQuery AJAX requests using $.ajaxSetup(). Before each AJAX request is performed, you check whether the request method is safe and that the current request is not cross-domain.
        If the request is unsafe, you set the X-CSRFToken header with the value obtained from the cookie. This setup will apply to all AJAX requests performed with jQuery.

        The CSRF token will be included in all AJAX requests that use unsafe HTTP methods, such as POST or PUT.
        ```
<a name="B53"></a>
- B.5.3. Performing AJAX requests with jQuery
    - Edit template/images/image/detail.html

        ```
        Rubah line ini ---
        {% with total_likes=image.users_like.count %}

        dengan ini ---
        {% with total_likes=image.users_like.count users_like=image.users_like.all %}

        ```
    - Replace

        ```
        {% for user in image.users_like.all %}

        with the following one:
        
        {% for user in users_like %}
        ```
    - Then, modify the <div> element with the image-info class as follows:

    ```html
    <div class="image-info">
        <div>
        <span class="count">
            <span class="total">{{ total_likes }}</span>
            like{{ total_likes|pluralize }}
        </span>
        <a href="#" data-id="{{ image.id }}" data-action="{% if request.user in users_like %}un{% endif %}like"
        class="like button">
            {% if request.user not in users_like %}
                Like
            {% else %}
                Unlike
            {% endif %}
        </a>
        </div>
            {{ image.description|linebreaks }}
    </div>
    ```
    ```
    Note:
    - First, you add another variable to the {% with %} template tag in order to store the results of the image users_like.all query and avoid executing it twice.

    - You use the variable for the for loop that iterates over the users that like this image.

    - You display the total number of users who like the image and include a link to like/unlike the image.

    - You check whether the user is in the related object set of users_like to display either like or unlike, based on the current relationship between the user and this image.

    - You add the following attributes to the <a> HTML element:
        • data-id: The ID of the image displayed.
        • data-action: The action to run when the user clicks on the link. This can be like or unlike.
    
        " Any attribute on any HTML element whose attribute name starts with data- is a data attribute. Data attributes are used to store custom data for your application. "

    - You will send the value of both attributes in the AJAX request to the image_like view.
    --> When a user clicks on the like/unlike link, you will perform the following actions on the client side:
        1. Call the AJAX view, passing the image ID and the action parameters to it
        2. If the AJAX request is successful, update the data-action attribute of the <a> HTML element with the opposite action (like / unlike), and modify its display text accordingly
        3. Update the total number of likes that is displayed


    ```
- templates/images/image/detail.html
    - Tambahkan {%domready%}

    ```js

    {% block domready %}
        $('a.like').click(function(e){
            e.preventDefault();
            $.post('{% url "images:like" %}',
            {
                id: $(this).data('id'),
                action: $(this).data('action')
            },
            function(data){
                if (data['status'] == 'ok')
                {
                    var previous_action = $('a.like').data('action');
                    // toggle data-action
                    $('a.like').data('action', previous_action == 'like' ?
                    'unlike' : 'like');
                    // toggle link text
                    $('a.like').text(previous_action == 'like' ? 'Unlike' : 'Like');
                    // update total likes
                    var previous_likes = parseInt($('span.count .total'). text());
                    $('span.count .total').text(previous_action == 'like' ? previous_likes + 1 : previous_likes - 1);
                }
            }
    );
    });
    {% endblock %}
    ```
    ```
    Note:
    1. You use the $('a.like') jQuery selector to find all <a> elements of the HTML document with the like class.

    2. You define a handler function for the click event. This function will be executed every time the user clicks on the like/unlike link.

    3. Inside the handler function, you use e.preventDefault() to avoid the default behavior of the <a> element. This will prevent the link from taking you anywhere.

    4. You use $.post() to perform an asynchronous POST request to the server. jQuery also provides a $.get() method to perform GET requests and a lowlevel $.ajax() method.

    5. You use Django's {% url %} template tag to build the URL for the AJAX request.

    6. You build the POST parameters dictionary to send in the request. The parameters are the ID and action parameters expected by your Django view. You retrieve these values from the <a> element's data-id and data-action attributes.

    7. You define a callback function that is executed when the HTTP response is received; it takes a data attribute that contains the content of the response.

    8. You access the status attribute of the data received and check whether it equals ok. If the returned data is as expected, you toggle the data-action attribute of the link and its text. This allows the user to undo their action.

    9. You increase or decrease the total likes count by one, depending on the action performed.
    ```
- Masuk ke detail page, coba tombol like/unlike apakah berhasil
- Saat menggunakan JavaScript, terutama operasi AJAX requests direkomendasikan menggunakan tool untuk debugging JavaScript dan HTTP requests. gunakan Inspect Element untuk mengakses web developer tools.

<a name="B6"></a>
### B.6. Creating custom decorators for your views
- Tujuan:
    - Let's restrict your AJAX views to allow only requests generated via AJAX.
        - The Django request object provides an is_ajax() method that checks whether the request is being made with XMLHttpRequest, which means that it is an AJAX request.
        - This value is set in the HTTP_X_REQUESTED_WITH HTTP header, which is
        included in AJAX requests by most JavaScript libraries.
    - you will create a decorator for checking the HTTP_X_REQUESTED_WITH header in your views.
        - A decorator is a function that takes another function and extends the behavior of the latter without explicitly modifying it.
        - If the concept of decorators is foreign to you, you might want to take a look at https://www.python.org/dev/peps/pep-0318/ before you continue reading.
        - Since your decorator will be generic and could be applied to any view, you will create a common Python package in your project.
- Buat directory berikut:

    ```
    common/
        __init__.py
        decorators.py
    ```
- Edit the decorators.py
    ```py
    from django.http import HttpResponseBadRequest

    def ajax_required(f):
        def wrap(request, *args, **kwargs):
            if not request.is_ajax():
                return HttpResponseBadRequest()
            return f(request, *args, **kwargs)
        wrap.__doc__=f.__doc__
        wrap.__name__=f.__name__
        return wrap
    ```
    ```
    Note:
    - code is your custom ajax_required decorator.
    - It defines a wrap function that returns an HttpResponseBadRequest object (HTTP 400 code) if the request is not AJAX. Otherwise, it returns the decorated function.
    ```
- Edit images/views.py
    - Tambahkan decorator diatas, ke image_like AJAX view:
    ```
    from common.decorators import ajax_required

    @ajax_required
    @login_required
    @require_POST
    def image_like(request):
        # ...
    ```
- https://127.0.0.1:8000/images/like/ maka akan mendapatkan HTTP 400 response.
- Build custom decorators for your views if you find that you are
repeating the same checks in multiple views.
<a name="B7"></a>
### B.7. Adding AJAX pagination to your list views
- Tujuan:
    - you need to list all bookmarked images on your website.
    - You will use AJAX pagination to build an infinite scroll functionality. Infinite scroll is achieved by loading the next results automatically when the user scrolls to the bottom of the page.
- view image_list()
    - image list view that will handle both standard browser requests and AJAX requests, including pagination.
    - When the user initially loads the image list page, you will display the first page of images.
    - When they scroll to the bottom of the page, you will load the following page of items via AJAX and append it to the bottom of the main page.
    - The same view will handle both standard and AJAX pagination.
- Edit images/views.py

    ```py

    from django.http import HttpResponse
    from django.core.paginator import Paginator, EmptyPage, \
    PageNotAnInteger

    @login_required
    def image_list(request):
        images = Image.objects.all()
        paginator = Paginator(images, 8)
        page = request.GET.get('page')
        try:
            images = paginator.page(page)
        except PageNotAnInteger:
            # If page is not an integer deliver the first page
            images = paginator.page(1)
        except EmptyPage:
            if request.is_ajax():
                # If the request is AJAX and the page is out of range
                # return an empty page
                return HttpResponse('')
            # If page is out of range deliver last page of results
            images = paginator.page(paginator.num_pages)
        if request.is_ajax():
            return render(request,'images/image/list_ajax.html', {'section': 'images', 'images': images})
        return render(request, 'images/image/list.html', {'section': 'images', 'images': images})
    ```
    ```
    Note:
    - you create a QuerySet to return all images from the database.

    - you build a Paginator object to paginate the results, retrieving eight images per page.

    - You get an EmptyPage exception if the requested page is out of range. If this is the case and the request is done via AJAX, you return an empty HttpResponse that will help you to stop the AJAX pagination on the client side.

    - You render the results to two different templates:
        • For AJAX requests, you render the list_ajax.html template.
        This template will only contain the images of the requested page.

        • For standard requests, you render the list.html template.
        This template will extend the base.html template to display the whole page and will include the list_ajax.html template to include the list of images.

    ```
- Edit images/urls.py
    ```
    path('', views.image_list, name='list'),

    ```
- Buat templates/images/image/list_ajax.html
    ```html
    {% load thumbnail %}
    {% for image in images %}
        <div class="image">
            <a href="{{ image.get_absolute_url }}">
                {% thumbnail image.image 300x300 crop="smart" as im %}
                <a href="{{ image.get_absolute_url }}"><img src="{{ im.url }}"></a>
            </a>
            <div class="info">
                <a href="{{ image.get_absolute_url }}" class="title">
                {{ image.title }}
                </a>
            </div>
        </div>
    {% endfor %}
    ```
    ```
    Note:
    - This template displays the list of images. You will use it to return results for AJAX requests.

    - In this code, you iterate over images and generate a square thumbnail for each image. You normalize the size of the thumbnails to 300x300 pixels.

    - You also use the smart cropping option. This option indicates that the image has to be incrementally cropped down to the requested size by removing slices from the edges with the least entropy.
    ```
- Buat templates/images/image/list.html
    ```html
    {% extends "base.html" %}
    {% block title %}Images bookmarked{% endblock %}
    {% block content %}
    <h1>Images bookmarked</h1>
    <div id="image-list">
        {% include "images/image/list_ajax.html" %}
    </div>
    {% endblock %}
    ```
    ```
    Note:
    - The list template extends the base.html template.
    - To avoid repeating code, you include the list_ajax.html template for displaying images.
    - The list.html template will hold the JavaScript code for loading additional pages when scrolling to the bottom of the page.

    ```
- Tambahkan kode berikut di templates/images/image/list.html
    ```js
    {% block domready %}
        var page = 1;
        var empty_page = false;
        var block_request = false;

    $(window).scroll(function() {
        var margin = $(document).height() - $(window).height() - 200;
        if($(window).scrollTop() > margin && empty_page == false && block_request == false) {
            block_request = true;
            page += 1;
            $.get('?page=' + page, function(data) {
                if(data == '') {
                    empty_page = true;
                }
                else {
                    block_request = false;
                    $('#image-list').append(data);
                }
            });
        }
    });
    {% endblock %}
    ```
    ```
    Note:
    - The preceding code provides the infinite scroll functionality.

    - You include the JavaScript code in the domready block that you defined in the base.html template.

    - The code is as follows:
        1. You define the following variables:
            ° page: Stores the current page number.
            ° empty_page: Allows you to know whether the user is on the last page and retrieves an empty page. As soon as you get an empty page, you will stop sending additional AJAX requests because you will assume that there are no more results.
            ° block_request: Prevents you from sending additional requests while an AJAX request is in progress.

        2. You use $(window).scroll() to capture the scroll event and also to define a handler function for it.

        3. You calculate the margin variable to get the difference between the total document height and the window height, because that's the height of the remaining content for the user to scroll. You subtract a value of 200 from the result so that you load the next page when the user is closer than 200 pixels
        to the bottom of the page.

        4. You only send an AJAX request if no other AJAX request is being done (block_request has to be false) and the user didn't get to the last page of results (empty_page is also false).

        5. You set block_request to true to avoid a situation where the scroll event triggers additional AJAX requests, and increase the page counter by one, in order to retrieve the next page.

        6. You perform an AJAX GET request using $.get() and receive the HTML response in a variable called data. The following are the two scenarios:

            ° The response has no content: You got to the end of the results, and there are no more pages to load. You set empty_page to true to prevent additional AJAX requests.

            ° The response contains data: You append the data to the HTML element with the image-list ID. The page content expands vertically, appending results when the user approaches the bottom of the page.
    ```
- https://127.0.0.1:8000/images/
    - tampilan pertama 8 images, lalu coba lakukan scroll pastikan semua image yang terbookmark berhasil tampil
    - jika perlu, gunakan firebug untuk tracking AJAX request dan debug javascript
- Edit account/templates/base.html
    ```html
        <li {% if section == "images" %}class="selected"{% endif %}>
        <a href="{% url "images:list" %}">Images</a>
        </li>
    ```

<a name="C"></a>
## C. Chapter 6: Tracking User Actions
- This chapter will cover the following points:<br>
    • Building a follow system<br>
    • Creating many-to-many relationships with an intermediary model<br>
    • Creating an activity stream application<br>
    • Adding generic relations to models
    • Optimizing QuerySets for related objects<br>
    • Using signals for denormalizing counts
    • Storing item views in Redis
<a name="C1"></a>
### C.1. Building a follow system
- Tujuan:
    - build a follow system in your project. your users will be able to
    follow each other and track what other users share on the platform.
    - The relationship
    between users is a many-to-many relationship: a user can follow multiple users and they, in turn, can be followed by multiple users.
<a name="C11"></a>
- C.1.1. Creating many-to-many relationships with an intermediary model
    - Tujuan:
        - In previous chapters, you created many-to-many relationships by adding the ManyToManyField to one of the related models and letting Django create the database table for the relationship.
        - but sometimes you may need to create an intermediary model for the relationship.
        - Creating an intermediary model is necessary when you want to store additional information for the relationship, for example, --the date when the relationship was created--, or --a field
        that describes the nature of the relationship.--</br>
    - create an intermediary model to build relationships between users.
        - There are two reasons for using an intermediary model:</br>
            • You are using the User model provided by Django and you want to avoid altering it</br>
            • You want to store the time when the relationship was created
        - Edit account/models.py

            ```py
            class Contact(models.Model):
                user_from = models.ForeignKey('auth.User',
                                            related_name='rel_from_set',
                                            on_delete=models.CASCADE)
                user_to = models.ForeignKey('auth.User',
                                            related_name='rel_to_set',
                                            on_delete=models.CASCADE)
                created = models.DateTimeField(auto_now_add=True,
                                                db_index=True)

                class Meta:
                    ordering = ('-created',)

                def __str__(self):
                    return f'{self.user_from} follows {self.user_to}'
            ```
            ```
            Note:
            - Contact Model:
                • user_from: A ForeignKey for the user who creates the relationship
                • user_to: A ForeignKey for the user being followed
                • created: A DateTimeField field with auto_now_add=True to store the time when the relationship was created
            
                - A database index is automatically created on the ForeignKey fields.
                - You use db_index=True to create a database index for the created field. This will improve query performance when ordering QuerySets by this field.

                - Using the ORM, you could create a relationship for a user, user1, following another user, user2, like this:
                    ```
                    user1 = User.objects.get(id=1)
                    user2 = User.objects.get(id=2)
                    Contact.objects.create(user_from=user1, user_to=user2)
                    ```

                - The related managers, `rel_from_set` and `rel_to_set`, will return a QuerySet for the Contact model.

            ```
            
        - access the end side of the relationship
            - In order to access the end side of the relationship from the User model, it would be desirable for User to contain a ManyToManyField, as follows:
                ```
                    following = models.ManyToManyField('self',
                                                        through=Contact,
                                                        related_name='followers',
                                                        symmetrical=False)
                ```
                ```
                    Note:
                    - In the preceding example, you tell Django to use your custom intermediary model for the relationship by adding `through=Contact` to the `ManyToManyField`.
                    - This is a many-to-many relationship from the User model to itself; you refer to 'self' in the ManyToManyField field to create a relationship to the same model.
                    
                    - When you need additional fields in a many-to-many relationship, create a custom model with a ForeignKey for each side of the relationship.
                    - Add a ManyToManyField in one of the related models and indicate to Django that your intermediary model should be used by including it in the through parameter.
                ```
            
            - If the User model was part of your application, you could add the previous field to the model. However, you can't alter the User class directly because it belongs to the django.contrib.auth application.
            - Let's take a slightly different approach by adding this field dynamically to the User model.
            - Edit account/models.py file:

            ```py
            from django.contrib.auth import get_user_model

            # Add following field to User dynamically
            user_model = get_user_model()
            user_model.add_to_class('following',
                                    models.ManyToManyField('self',
                                        through=Contact,
                                        related_name='followers',
                                        symmetrical=False))
            ```
            ```
            Note:
            - you retrieve the user model by using the generic function get_user_model(), which is provided by Django.

            - You use the add_to_class() method of Django models to monkey patch the User model.
                * Be aware that using add_to_class() is not the recommended way of adding fields to models.
                * However, you take advantage of using it in this case to avoid creating a custom user model, keeping all the advantages of Django's built-in User model.

            - You also simplify the way that you retrieve related objects using the Django ORM with user.followers.all() and user.following.all().

            - You use the intermediary Contact model and avoid complex queries that would involve additional database joins, as would have been the case had you defined the relationship in your custom Profile model.

            - The table for this many-to-many relationship will be created using the Contact model. Thus, the ManyToManyField, added dynamically, will not imply any database changes for the Django User model.

            - Keep in mind that, in most cases, it is preferable to add fields to the Profile model you created before, instead of monkey patching the User model.
            - Ideally, you shouldn't alter the existing Django User model. Django allows you to use custom user models.
            - If you want to use your custom user model, take a look at the documentation at https://docs.djangoproject.com/en/3.0/topics/auth/customizing#specifying-a-custom-user-model.

            - Note that the relationship includes `symmetrical=False`. When you define a ManyToManyField in the model creating a relationship with itself, Django forces the relationship to be symmetrical.
            - In this case, you are setting symmetrical=False to define a non-symmetrical relationship (if I follow you, it doesn't mean that you automatically follow me).

            - When you use an intermediary model for many-to-many relationships, some of the related manager's methods are disabled, such as add(), create(), or remove(). You need to create or delete instances of the intermediary model instead.
            ```
    - Migration
        ```
        python manage.py makemigrations account
        python manage.py migrate account
        ```

<a name="C12"></a>
- C.1.2. Creating list and detail views for user profiles
    - Edit account/views.py

        ```py

        @login_required
        def user_list(request):
            users = User.objects.filter(is_active=True)
            return render(request,
                        'account/user/list.html',
                        {'section': 'people',
                        'users': users})
        @login_required
        def user_detail(request, username):
            user = get_object_or_404(User,
                                    username=username,
                                    is_active=True)
            return render(request,
                        'account/user/detail.html',
                        {'section': 'people',
                        'user': user})
        ```
        ```
        Note:
        - These are simple list and detail views for User objects.
        - The user_list view gets all active users.
        - is_active flag --> to designate whether the user account is considered active.
        - You filter the query by is_active=True to return only active users.
        - This view returns all results, but you can improve it by adding pagination in the same way as you did for the image_list view.
        - The user_detail view uses the get_object_or_404() shortcut to retrieve the active user with the given username. The view returns an HTTP 404 response if no active user with the given username is found.

        ```
    - Edit account/urls.py

        ```py

        urlpatterns = [
            # ...
            path('users/', views.user_list, name='user_list'),
            path('users/<username>/', views.user_detail, name='user_detail'),
            ]

        ```
        ```
        Note:
        - You will use the user_detail URL pattern to generate the canonical URL for users.
        ```
        ```
        ALTERNATIVES:
        - You have already defined a get_absolute_url() method in a model to return the canonical URL for each object
        - Another way to specify the URL for a model is by adding the ABSOLUTE_URL_OVERRIDES setting to your project.
        ```
        ```PY
        # Edit the settings.py
        from django.urls import reverse_lazy

        ABSOLUTE_URL_OVERRIDES = {
            'auth.user': lambda u: reverse_lazy('user_detail', args=[u.username])
        }
        ```
        ```
        Note:
        - Django adds a get_absolute_url() method dynamically to any models that appear in the ABSOLUTE_URL_OVERRIDES setting.
        - This method returns the corresponding URL for the given model specified in the setting.
        - You return the user_detail URL for the given user.

        Now, you can use get_absolute_url() on a User instance to retrieve its corresponding URL.:
        - Open the Python shell with the python manage.py shell command and run the following code to test it:

        >>> from django.contrib.auth.models import User
        >>> user = User.objects.latest('id')
        >>> str(user.get_absolute_url())
        '/account/users/ellington/'

        - The returned URL is as expected.

        ```
    - Buka account/templates/account, Buat directory berikut:

        ```
        /user/
            detail.html
            list.html
        ```
    - Edit ccount/user/list.html

        ```html

        {% extends "base.html" %}
        {% load thumbnail %}
        {% block title %}People{% endblock %}

        {% block content %}
            <h1>People</h1>
            <div id="people-list">
                {% for user in users %}
                <div class="user">
                    <a href="{{ user.get_absolute_url }}">
                        <img src="{% thumbnail user.profile.photo 180x180 %}">
                    </a>
                    <div class="info">
                        <a href="{{ user.get_absolute_url }}" class="title">
                            {{ user.get_full_name }}
                        </a>
                    </div>
                </div>
            {% endfor %}
            </div>

        {% endblock %}
        ```
        ```
        Note:
        - The preceding template allows you to list all the active users on the site.
        - You iterate over the given users and use the {% thumbnail %} template tag from easythumbnails to generate profile image thumbnails.
        ```
    - Buka template/base.html

        ```html

        <li {% if section == "people" %}class="selected"{% endif %}>
            <a href="{% url "user_list" %}">People</a>
        </li>
        ```
    - Run
        - python manage.py runserver
        - open http://127.0.0.1:8000/account/users/
        - Maka menu people akan muncul daftar user beserta thumbnail
        - Jika ada thumbnail tidak muncul, buka settings.py > THUMBNAIL_DEBUG = True, untuk debug
    - Edit account/user/detail.html

        ```html
        {% extends "base.html" %}
        {% load thumbnail %}
        {% block title %}{{ user.get_full_name }}{% endblock %}

        {% block content %}
        <h1>{{ user.get_full_name }}</h1>
            <div class="profile-info">
                <img src="{% thumbnail user.profile.photo 180x180 %}" class="userdetail">
            </div>
            {% with total_followers=user.followers.count %}
                <span class="count">
                    <span class="total">{{ total_followers }}</span>
                    follower{{ total_followers|pluralize }}
                </span>
                <a href="#" data-id="{{ user.id }}" data-action="{% if request.user in user.followers.all %}un{% endif %}follow" class="follow button">
                    {% if request.user not in user.followers.all %}
                        Follow
                    {% else %}
                        Unfollow
                    {% endif %}
                </a>
                <div id="image-list" class="image-container">
                    {% include "images/image/list_ajax.html" with images=user.images_created.all %}
                </div>
            {% endwith %}
        {% endblock %}
        ```
        ```
        Note:
        # Make sure that no template tag is split into multiple lines; Django doesn't support multiple line tags.

        - In the detail template, you display the user profile and use the {% thumbnail %} template tag to display the profile image.

        - You show the total number of followers and a link to follow or unfollow the user.

        - You perform an AJAX request to follow/unfollow a particular user.

        - You add data-id and data-action attributes to the <a> HTML element, including the user ID and the initial action to perform when the link element is clicked – follow or unfollow, which depends on the user requesting the page being a follower of this other user or not, as the case may be.

        - You display the images bookmarked by the user, including the images/image/list_ajax.html template.
        ```
    - Open your browser again and click on a user who has bookmarked some images. you will see detail user profile view page include image that has been bookmarked

<a name="C13"></a>
- C.1.3. Building an AJAX view to follow users
    - Tujuan : create follow/unfollow a user using AJAX.
    - Buka account/views.py

        ```py
        from django.http import JsonResponse
        from django.views.decorators.http import require_POST
        from common.decorators import ajax_required
        from .models import Contact

        @ajax_required
        @require_POST
        @login_required
        def user_follow(request):
            user_id = request.POST.get('id')
            action = request.POST.get('action')
            if user_id and action:
                try:
                    user = User.objects.get(id=user_id)
                    if action == 'follow':
                        Contact.objects.get_or_create(user_from=request.user,user_to=user)
                    else:
                        Contact.objects.filter(user_from=request.user,user_to=user).delete()
                    return JsonResponse({'status':'ok'})
                except User.DoesNotExist:
                    return JsonResponse({'status':'error'})
            return JsonResponse({'status':'error'})

        ```
        ```
        Note:
        - The `user_follow` view is quite similar to the `image_like` view that you created before.
        - Since you are using a custom intermediary model for the user's many-tomany relationship, the default add() and remove() methods of the automatic manager of ManyToManyField are not available.
        - You use the intermediary Contact model to create or delete user relationships.

        ```
    - Edit account/urls.py

        ```py

        path('users/follow/', views.user_follow, name='user_follow'),
        ```
        ```
        Note:
        - Ensure that you place the preceding pattern before the user_detail URL pattern.
        - Otherwise, any requests to /users/follow/ will match the regular expression of the user_detail pattern and that view will be executed instead.
        - Remember that in every HTTP request, Django checks the requested URL against each pattern in order of appearance and stops at the first match.
        ```
    - Edit account/user/detail.html

        ```js

        {% block domready %}
            $('a.follow').click(function(e){
                e.preventDefault();
                $.post('{% url "user_follow" %}',
                    {
                        id: $(this).data('id'),
                        action: $(this).data('action')
                    },
                    function(data){
                        if (data['status'] == 'ok') {
                            var previous_action = $('a.follow').data('action');
                            // toggle data-action
                            $('a.follow').data('action', previous_action == 'follow' ? 'unfollow' : 'follow');
                            // toggle link text
                            $('a.follow').text(
                            previous_action == 'follow' ? 'Unfollow' : 'Follow');
                            // update total followers
                            var previous_followers = parseInt(
                                    $('span.count .total').text());
                                    $('span.count .total').text(previous_action == 'follow' ? previous_followers + 1 : previous_followers - 1);
                        }
                    }
                );
            });
        {% endblock %}
        ```
        ```
        Note:
        - The preceding code is the JavaScript code to perform the AJAX request to follow or unfollow a particular user and also to toggle the follow/unfollow link.

        - You use jQuery to perform the AJAX request and set both the data-action attribute and the text of the HTML <a> element based on its previous value.

        - When the AJAX action is performed, you also update the total followers count displayed on the page.
        ```
    - Buka detail page salah satu user profile, coba Follow/unfollow, coba lihat perubahan follower yang terjadi
<a name="C2"></a>
- Building a generic activity stream application
    - Tujuan:
        - You are going to build an activity stream application so that every user can see the recent interactions of the users they follow.
        - To do so, you will need a model to save the actions performed by users on the website and a simple way to add actions to the feed.
    - Buat app baru bernama 'action'

        ```bash

        python manage.py startapp actions
        ```
    - registrasi app pada settings.py

        ```py

        INSTALLED_APPS = [
            # ...
            'actions.apps.ActionsConfig',
            ]
        ```
    - Edit actions/models.py

        ```py

        from django.db import models

        class Action(models.Model):
            user = models.ForeignKey('auth.User',
                                    related_name='actions',
                                    db_index=True,
                                    on_delete=models.CASCADE)
            verb = models.CharField(max_length=255)
            created = models.DateTimeField(auto_now_add=True,
                                            db_index=True)

            class Meta:
                ordering = ('-created',)
        ```
        ```
        Note:
        - The preceding code shows the Action model that will be used to store user activities.
        - The fields of this model are as follows:
            • user: The user who performed the action; this is a ForeignKey to the Django User model.
            • verb: The verb describing the action that the user has performed.
            • created: The date and time when this action was created. You use auto_ now_add=True to automatically set this to the current datetime when the object is saved for the first time in the database.
        ```
        ```
        - With this basic model, you can only store actions, such as user X did something.
        - You need an extra ForeignKey field in order to save actions that involve a target object, such as user X bookmarked image Y or user X is now following user Y.
        - As you already know, a normal ForeignKey can point to only one model.
        - Instead, you will need a way for the action's target object to be an instance of an existing model.
        - This is what the -- Django contenttypes framework -- will help you to do.

        
        ```
<a name="C21"></a>
- C.2.1. Using the contenttypes framework
    - Tujuan:
        - Docs: https://docs.djangoproject.com/en/3.0/ref/contrib/contenttypes/
        - Django includes a contenttypes framework located at `django.contrib.contenttypes`.
        - This application can track all models installed in your project and provides a generic interface to interact with your models.
        - ----->
        - The django.contrib.contenttypes application is included in the INSTALLED_APPS setting by default when you create a new project using the startproject command.
        - The contenttypes application contains a ContentType model.
        - Instances of this model represent the actual models of your application, and new instances of ContentType are automatically created when new models are installed in your project.
        - The ContentType model has the following fields:
            - app_label: This indicates the name of the application that the model belongs to. This is automatically taken from the app_label attribute of the model Meta options. For example, your Image model belongs to the images application.
            - model: The name of the model class.
            - name: This indicates the human-readable name of the model. This is automatically taken from the verbose_name attribute of the model Meta options.
        - Let's take a look at how you can interact with ContentType objects. Open the shell using the -- python manage.py shell -- command.
        - You can obtain the ContentType object corresponding to a specific model by performing a query with the app_label and model attributes, as follows:

            ```
            >>> from django.contrib.contenttypes.models import ContentType
            >>> image_type = ContentType.objects.get(app_label='images', model='image')
            >>> image_type
            <ContentType: images | image>

            ```
        - You can also retrieve the model class from a ContentType object by calling its model_class() method:

            ```
            >>> image_type.model_class()
            <class 'images.models.Image'>
            ```
        - It's also common to get the ContentType object for a particular model class, as follows:

            ```
            >>> from images.models import Image
            >>> ContentType.objects.get_for_model(Image)
            <ContentType: images | image>
            ```

<a name="C22"></a>
- C.2.2. Adding generic relations to your models
    - Tujuan:
        - In generic relations, ContentType objects play the role of pointing to the model used for the relationship.
        - You will need three fields to set up a generic relation in a model:
            - A ForeignKey field to ContentType: --> This will tell you the model for the relationship
            - A field to store the primary key of the related object: --> This will usually be a PositiveIntegerField to match Django's automatic primary key fields
            - A field to define and manage the generic relation using the two previous fields: --> The contenttypes framework offers a GenericForeignKey field for this purpose
    - Edit actions/models.py

        ```py
        from django.db import models
        from django.contrib.contenttypes.models import ContentType
        from django.contrib.contenttypes.fields import GenericForeignKey

        class Action(models.Model):
            user = models.ForeignKey('auth.User',
                                    related_name='actions',
                                    db_index=True,
                                    on_delete=models.CASCADE)
            verb = models.CharField(max_length=255)
            target_ct = models.ForeignKey(ContentType,
                                        blank=True,
                                        null=True,
                                        related_name='target_obj',
                                        on_delete=models.CASCADE)
            target_id = models.PositiveIntegerField(null=True,
                                                    blank=True,
                                                    db_index=True)
            target = GenericForeignKey('target_ct', 'target_id')
            created = models.DateTimeField(auto_now_add=True,
                                            db_index=True)
            class Meta:
                ordering = ('-created',)
        ```
        ```
        Note:
        - You have added the following fields to the Action model:
            • target_ct: A ForeignKey field that points to the ContentType model
            • target_id: A PositiveIntegerField for storing the primary key of the related object
            • target: A GenericForeignKey field to the related object based on the combination of the two previous fields

        - Django does not create any field in the database for GenericForeignKey fields.
        - The only fields that are mapped to database fields are `target_ct` and `target_id`.
        - Both fields have blank=True and null=True attributes, so that a target object is not required when saving Action objects.

        " You can make your applications more flexible by using generic relations instead of foreign keys."

        ```
    - Migrate

        ```
        python manage.py makemigrations actions
        python manage.py migrate

        ```
    - Edit action/admin.py untuk Registrasi account app ke admin

        ```py
        from django.contrib import admin
        from .models import Action

        @admin.register(Action)
        class ActionAdmin(admin.ModelAdmin):
            list_display = ('user', 'verb', 'target', 'created')
            list_filter = ('created',)
            search_fields = ('verb',)
        ```
    - Run:

        ```
        python manage.py runserver

        http://127.0.0.1:8000/admin/actions/action/add/

        ```
        ```
        Note:
        - As you will notice in the preceding admin panel page, only the `target_ct` and `target_id` fields that are mapped to actual database fields are shown.

        - The `GenericForeignKey` field does not appear in the form.

        - The `target_ct` field allows you to select any of the registered models of your Django project.

        - You can restrict the content types to choose from a limited set of models using the `limit_choices_to` attribute in the `target_ct` field; the `limit_choices_to` attribute allows you to restrict the content of `ForeignKey` fields to a specific set of values.
        ```
    - Buat actions/utils.py
        - Tujuan:
            - You need to define a shortcut function that will allow you to create new Action objects in a simple way.
        - Edit utils.py

            ```py
            from django.contrib.contenttypes.models import ContentType
            from .models import Action

            def create_action(user, verb, target=None):
                action = Action(user=user, verb=verb, target=target)
                action.save()
            ```
            ```
            Note:
            - The create_action() function allows you to create actions that optionally include a target object.
            - You can use this function anywhere in your code as a shortcut to add new actions to the activity stream.
            ```

<a name="C23"></a>
- C.2.3. Avoiding duplicate actions in the activity stream
    - Tujuan:
        - improve the create_action() function to skip obvious duplicated actions.
        - Sometimes, your users might click several times on the LIKE or UNLIKE button or perform the same action multiple times in a short period of time.
        - This will easily lead to storing and displaying duplicate actions.
    - Edit utils.py

        ```py
        import datetime
        from django.utils import timezone
        from django.contrib.contenttypes.models import ContentType
        from .models import Action

        def create_action(user, verb, target=None):
            # check for any similar action made in the last minute
            now = timezone.now()
            last_minute = now - datetime.timedelta(seconds=60)
            similar_actions = Action.objects.filter(user_id=user.id,
                                                    verb= verb,
                                                    created__gte=last_minute)
            if target:
                target_ct = ContentType.objects.get_for_model(target)
                similar_actions = similar_actions.filter(
                                                    target_ct=target_ct,
                                                    target_id=target.id)
            if not similar_actions:
                # no existing actions found
                action = Action(user=user, verb=verb, target=target)
                action.save()
                return True
            return False
        ```
        ```
        Note: 
        - You have changed the create_action() function to avoid saving duplicate actions and return Boolean to tell you whether the action was saved.
        - This is how you avoid duplicates:
            • First, you get the current time using the timezone.now() method provided by Django.
                - This method does the same as datetime.datetime.now() but returns a timezone-aware object.
                - Django provides a setting called USE_TZ to enable or disable timezone support.
                - The default settings.py file created using the startproject command includes USE_TZ=True.

            • You use the last_minute variable to store the datetime from one minute ago and retrieve any identical actions performed by the user since then.

            • You create an Action object if no identical action already exists in the last minute. You return True if an Action object was created, or False otherwise.
        ```

<a name="C24"></a>
- C.2.4. Adding user actions to the activity stream
    - Tujuan:
        - add some actions to your views to build the activity stream for your users.
        - You will store an action for each of the following interactions:<br>
            • A user bookmarks an image<br>
            • A user likes an image<br>
            • A user creates an account<br>
            • A user starts following another user<br>
    - Edit images/views.py
        - add import

            ```py
            
            from actions.utils import create_action

            ```
        - In the `image_create()` view, add `create_action()` after saving the image, like this:

            ```py

            new_item.save()
            create_action(request.user, 'bookmarked image', new_item)

            ```
        - In the `image_like()` view, add `create_action()` after adding the user to the `users_like` relationship, as follows:

            ```py

            image.users_like.add(request.user)
            create_action(request.user, 'likes', image) 
            ```
    - Edit account/views.py
        - add import

            ```py
            
            from actions.utils import create_action
            ```
        - In the `register()` view, add `create_action()` after creating the `Profile` object, as follows:

            ```py

            Profile.objects.create(user=new_user)
            create_action(new_user, 'has created an account')
            ```
        - In the `user_follow()` view, add `create_action()`:

            ```py

            Contact.objects.get_or_create(user_from=request.user, user_to=user)
            create_action(request.user, 'is following', user)
            ```
    - As you can see in the preceding code, thanks to your Action model and your helper function, it's very easy to save new actions to the activity stream.    
<a name="C25"></a>
- C.2.5. Displaying the activity stream
    - Tujuan:
        - you need a way to display the activity stream for each user.
        - You will include the activity stream in the user's dashboard.
    - Edit account/views.py
        - Import the `Action` model and modify the `dashboard()` view, as follows:

        ```py
        from actions.models import Action

        @login_required
        def dashboard(request):
            # Display all actions by default
            actions = Action.objects.exclude(user=request.user)
            following_ids = request.user.following.values_list('id',flat=True)

            if following_ids:
                # If user is following others, retrieve only their actions
                actions = actions.filter(user_id__in=following_ids)
            actions = actions[:10]

            return render(request,
                        'account/dashboard.html',
                        {'section': 'dashboard',
                        'actions': actions})
        ```
        ```
        Note:
        - you retrieve all actions from the database, excluding the ones performed by the current user.

        - By default, you retrieve the latest actions performed by all users on the platform.

        - If the user is following other users, you restrict the query to retrieve only the actions performed by the users they follow.

        - Finally, you limit the result to the first 10 actions returned.

        - You don't use order_by() in the QuerySet because you rely on the default ordering that you provided in the Meta options of the Action model.

        - Recent actions will come first since you set ordering = ('-created',) in the Action model.
        ```

<a name="C26"></a>
- C.2.6. Optimizing QuerySets that involve related objects
    - Tujuan:
        - Every time you retrieve an Action object, you will usually access its related User object and the user's related Profile object.
        - The Django ORM offers a simple way to retrieve related objects at the same time, thereby avoiding additional queries to the database.

<a name="C27"></a>
- C.2.7. Using select_related()
    - Tujuan:
        - Django offers a QuerySet method called `select_related()` that allows you to retrieve related objects for one-to-many relationships.
        - This translates to a single, more complex QuerySet, but you avoid additional queries when accessing the related objects.
        - The `select_related` method is for `ForeignKey` and `OneToOne` fields.
        - It works by performing a SQL JOIN and including the fields of the related object in the SELECT statement.
    - To take advantage of `select_related()`:
        - edit the following line of the preceding code:

            ```py

            actions = actions[:10]
            ```
        - Also, add `select_related` to the fields that you will use, like this:

            ```py

            actions = actions.select_related('user', 'user__profile')[:10]
            ```
            ```
            Note:
            - You use `user__profile` to join the `Profile` table in a single SQL query.
            - If you call `select_related()` without passing any arguments to it, it will retrieve objects from all `ForeignKey` relationships.
            - Always limit `select_related()` to the relationships that will be accessed afterward.
            - Using select_related() carefully can vastly improve execution time.
            ```
<a name="C28"></a>
- C.2.8. Using prefetch_related()
    - Problem:
        - `select_related()` will help you to boost performance for retrieving related objects in one-to-many relationships.
        - However, `select_related()` doesn't work for many-to-many or many-to-one relationships (`ManyToMany` or reverse `ForeignKey` fields).
    - Solusi:
        - Django offers a different QuerySet method called `prefetch_related` that works for many-to-many and many-to-one relationships in addition to the relationships supported by `select_related()`.
        - The `prefetch_related()` method performs a separate lookup for each relationship and joins the results using Python.
        - This method also supports the prefetching of `GenericRelation` and `GenericForeignKey`.
    - Edit account/views.py
        - complete your query by adding `prefetch_related()` to it for the target `GenericForeignKey` field, as follows:

            ```py
            actions = actions.select_related('user', 'user__profile')\
                        .prefetch_related('target')[:10]
            ```
            ```
            Note:
            This query is now optimized for retrieving the user actions, including related objects.
            ```
<a name="C29"></a>
- C.2.9. Creating templates for actions
    - Tujuan:
        - create the template to display a particular Action object.
    - Add the following file structure to it:

        ```
        actions/
            action/
            detail.html
        ```
    - Edit template/actions/action/detail.html

        ```html

        {% load thumbnail %}
        {% with user=action.user profile=action.user.profile %}
        
        <div class="action">
            <div class="images">
                {% if profile.photo %}
                    {% thumbnail user.profile.photo "80x80" crop="100%" as im %}
                    <a href="{{ user.get_absolute_url }}">
                        <img src="{{ im.url }}" alt="{{ user.get_full_name }}" class="item-img">
                    </a>
                {% endif %}
                {% if action.target %}
                    {% with target=action.target %}
                        {% if target.image %}
                            {% thumbnail target.image "80x80" crop="100%" as im %}
                            <a href="{{ target.get_absolute_url }}">
                                <img src="{{ im.url }}" class="item-img">
                            </a>
                        {% endif %}
                    {% endwith %}
                {% endif %}
            </div>
            <div class="info">
                <p>
                    <span class="date">{{ action.created|timesince }} ago</span>
                    <br />
                    <a href="{{ user.get_absolute_url }}">
                        {{ user.first_name }}
                    </a>
                    {{ action.verb }}
                    {% if action.target %}
                        {% with target=action.target %}
                            <a href="{{ target.get_absolute_url }}">{{ target }}</a>
                        {% endwith %}
                    {% endif %}
                </p>
            </div>
        </div>
        {% endwith %}

        ```
        ```
        Note:
        - This is the template used to display an `Action` object.
        - First, you use the {% with %} template tag to retrieve the user performing the action and the related Profile object.
        - Then, you display the image of the target object if the Action object has a related target object.
        - Finally, you display the link to the user who performed the action, the verb, and the `target` object, if any.
        ```
    - Edit template/account/dashboard.html
        - append the following code to the bottom of the `content` block:

            ```html
            <h2>What's happening</h2>
                <div id="action-list">
                    {% for action in actions %}
                    {% include "actions/action/detail.html" %}
                    {% endfor %}
                </div>

            ```
    - Run
        - http://127.0.0.1:8000/account/
        - Log in as an existing user and perform several actions so that they get stored in the database.
        - Then, log in using another user, follow the previous user, and take a look at the generated action stream on the dashboard page.
    - Summary
        - You just created a complete activity stream for your users, and you can easily add new user actions to it.
        - You can also add infinite scroll functionality to the activity stream by implementing the same AJAX paginator that you used for the image_list view.

<a name="C3"></a>
### C.3. Using signals for denormalizing counts
- Tujuan:
    - There are some cases when you may want to denormalize your data.
    - Denormalization is making data redundant in such a way that it optimizes read performance.
    - For example, you might be copying related data to an object to avoid expensive read queries to the database when retrieving the related data.
    - You have to be careful about denormalization and only start using it when you really need it.
    - The biggest issue you will find with denormalization is that it's difficult to keep your denormalized data updated.
- Let's take a look at an example of how to improve your queries by denormalizing counts.
    - You will denormalize data from your `Image` model and use Django signals to keep the data updated.
<a name="C31"></a>
- C.3.1. Working with signals
    - Tujuan:
        - Docs: https://docs.djangoproject.com/en/3.0/ref/signals/
        - Django comes with a signal dispatcher that allows receiver functions to get notified when certain actions occur.
        - Signals are very useful when you need your code to do something every time something else happens.
        - Signals allow you to decouple logic:
            - you can capture a certain action, regardless of the application
            - or code that triggered that action, and implement logic that gets executed whenever that action occurs.
        - For example, you can build a signal receiver function that gets executed every time a User object is saved.
        - You can also create your own signals so that others can get notified when an event happens.
        - Django provides several signals for models located at `django.db.models.signals`. Some of these signals are as follows:<br>
            • pre_save and post_save are sent before or after calling the save() method of a model<br>
            • pre_delete and post_delete are sent before or after calling the delete() method of a model or QuerySet<br>
            • m2m_changed is sent when a ManyToManyField on a model is changed<br>
        - Let's say you want to retrieve images by popularity. You can use the Django aggregation functions to retrieve images ordered by the number of users who like them.
        - Remember that you used Django aggregation functions in Chapter 3, Extending Your Blog Application. The following code will retrieve images according to their number of likes:

        ```py

        from django.db.models import Count
        from images.models import Image

        images_by_popularity = Image.objects.annotate(
        total_likes=Count('users_like')).order_by('-total_likes')
        ```
        ```
        Note:
        - However, ordering images by counting their total likes is more expensive in terms of performance than ordering them by a field that stores total counts.
        - You can add a field to the Image model to denormalize the total number of likes to boost performance in queries that involve this field.
        - The issue is how to keep this field updated.

        ```
    - Edit images/models.py
        - add the following total_likes field to the Image model:

            ```py
            class Image(models.Model):
                # ...
                total_likes = models.PositiveIntegerField(db_index=True,
                default=0)

            ```
            ```
            Note:
            - The total_likes field will allow you to store the total count of users who like each image.
            - Denormalizing counts is useful when you want to filter or order QuerySets by them.

            " There are several ways to improve performance that you have to take into account before denormalizing fields. Consider database indexes, query optimization, and caching before starting to denormalize your data. "

            ```
    - Migrate
        ```
        python manage.py makemigrations images
        python manage.py migrate images
        ```
    - Buat images/signal.py, --> You need to attach a receiver function to the m2m_changed signal.

        ```py

        from django.db.models.signals import m2m_changed
        from django.dispatch import receiver
        from .models import Image

        @receiver(m2m_changed, sender=Image.users_like.through)
        def users_like_changed(sender, instance, **kwargs):
            instance.total_likes = instance.users_like.count()
            instance.save()

        ```
        ```
        Note:
        - First, you register the users_like_changed function as a receiver function using the receiver() decorator.
        - You attach it to the m2m_changed signal.
        - Then, you connect the function to Image.users_like.through so that the function is only called if the m2m_changed signal has been launched by this sender.
        - There is an alternate method for registering a receiver function; it consists of using the connect() method of the Signal object.
        ```
        ```
        ===========
        - Django signals are synchronous and blocking.
        - Don't confuse signals with asynchronous tasks.
        - However, you can combine both to launch asynchronous tasks when your code gets notified by a signal.
        - You will learn to create asynchronous tasks with Celery in Chapter 7, Building an Online Shop.
        ```
        ```
        - You have to connect your receiver function to a signal so that it gets called every time the signal is sent.
        - The recommended method for registering your signals is by importing them in the ready() method of your application configuration class.
        - Django provides an application registry that allows you to configure and introspect your applications.
        ```
<a name="C32"></a>
- C.3.2. Application configuration classes
    - Tujuan:
        - Docs: https://docs.djangoproject.com/en/3.0/ref/applications/
        - Django allows you to specify configuration classes for your applications.
        - When you create an application using the startapp command, Django adds an apps.py file to the application directory, including a basic application configuration that inherits from the AppConfig class.
        - The application configuration class allows you to store metadata and the configuration for the application, and it provides introspection for the application.
        - ---------------------------
        - In order to register your signal `receiver` functions, when you use the `receiver()` decorator, you just need to import the signals module of your application inside the `ready()` method of the application configuration class.
        - This method is called as soon as the application registry is fully populated.
        - Any other initializations for your application should also be included in this method.
    - Edit images/apps.py

        ```py
        from django.apps import AppConfig

        class ImagesConfig(AppConfig):
            name = 'images'

            def ready(self):
                # import signal handlers
                import images.signals

        ```
        ```
        Note:
        - You import the signals for this application in the ready() method so that they are imported when the images application is loaded.
        ```
    - Run
        - python manage.py runserver
        - Open your browser to view an image detail page and click on the LIKE button.
        - http://127.0.0.1:8000/admin/images/image/1/change/
        - take a look at the total_likes attribute. You should see that the total_likes attribute is updated with the total number of users who like the image
    - Now, you can use the total_likes attribute to order images by popularity or display the value anywhere, avoiding using complex queries to calculate it.
    - Consider the following query to get images ordered according to their likes count:

        ```py

        from django.db.models import Count

        images_by_popularity = Image.objects.annotate(likes=Count('users_like'))
                                                    .order_by('-likes')

        ```
        - The preceding query can now be written as follows:

        ```py
        
        images_by_popularity = Image.objects.order_by('-total_likes')
        ```
    - This results in a less expensive SQL query. This is just an example of how to use Django signals.
        ```
        ------------------
        Use signals with caution since they make it difficult to know the control flow.
        In many cases, you can avoid using signals if you know which receivers need to be notified.
        ```
    - You will need to set initial counts for the rest of the Image objects to match the current status of the database.
        - python manage.py shell
        ```
        from images.models import Image

        for image in Image.objects.all():
            image.total_likes = image.users_like.count()
            image.save()
        ```
        ```
        Note:
        The likes count for each image is now up to date.
        ```
<a name="C4"></a>
- Using Redis for storing item views
    - Tujuan:
        - Redis is an advanced key/value database that allows you to save different types of data.
        - It also has extremely fast I/O operations.
        - Redis stores everything in memory, but the data can be persisted by dumping the dataset to disk every once in a while, or by adding each command to a log.
        - Redis is very versatile compared to other key/value stores:
            - it provides a set of powerful commands
            - supports diverse data structures, such as strings, hashes, lists, sets, ordered sets, and even bitmaps or HyperLogLogs.
        - Although SQL is best suited to schema-defined persistent data storage, Redis offers numerous advantages when dealing with rapidly changing data, volatile storage, or when a quick cache is needed.

<a name="C41"></a>
- C.4.1. Installing Redis
    - Linux
        - download the latest Redis version from https://redis.io/download
        - Unzip the tar.gz file, enter the redis directory, and compile Redis using the make command, as follows:
            ```
            cd redis-5.0.8
            make
            ```
    - Windows Subsystem for Linux (WSL)
        - You can read instructions on enabling WSL and installing Redis at https://redislabs.com/blog/redis-on-windows-10/
    - After installing Redis, use the following shell command to start the Redis server:
        ```
        src/redis-server
        ```
        ```
        By default, Redis runs on port 6379.
        you can specify a custom port using the --port flag, for example, redis-server --port 6655.

        ```
    - Keep the Redis server running and open another shell. Start the Redis client with the following command:
        ```
        src/redis-cli

        You will see the Redis client shell prompt, like this:
        127.0.0.1:6379>
        ```
    - Enter the SET command in the Redis shell to store a value in a key:
        ```
        127.0.0.1:6379> SET name "Peter"
        OK
        ```
        ```
        Note:
        - The preceding command creates a name key with the string value "Peter" in the Redis database.
        - The OK output indicates that the key has been saved successfully.
        ```
    - Next, retrieve the value using the GET command, as follows:
        ```
        127.0.0.1:6379> GET name
        "Peter" 
        ```
    - You can also check whether a key exists using the EXISTS command. This command returns 1 if the given key exists, and 0 otherwise:
        ```
        127.0.0.1:6379> EXISTS name
        (integer) 1
        ```
    - You can set the time for a key to expire using the EXPIRE command, which allows you to set time-to-live in seconds.
        ```
        127.0.0.1:6379> GET name
        "Peter"
        127.0.0.1:6379> EXPIRE name 2
        (integer) 1

        Wait for two seconds and try to get the same key again:
        127.0.0.1:6379> GET name
        (nil)
            * The (nil) response is a null response and means that no key has been found.
        ``` 
    - You can also delete any key using the DEL command, as follows:
        ```
        127.0.0.1:6379> SET total 1
        OK
        127.0.0.1:6379> DEL total
        (integer) 1
        127.0.0.1:6379> GET total
        (nil)
        ```
    - These are just basic commands for key operations.
    - Redis commands at https://redis.io/commands
    - Redis data types at https://redis.io/topics/data-types

<a name="C42"></a>
- Using Redis with Python
    - Docs: https://redis-py.readthedocs.io/
    - pip install redis==3.4.1
    - python manage.py shell --> execute the following code:
        ```
        >>> import redis
        >>> r = redis.Redis(host='localhost', port=6379, db=0)
        ```
        ```
        Note: 
        - The preceding code creates a connection with the Redis database.
        - In Redis, databases are identified by an integer index instead of a database name. By default, a client is connected to the database 0.
        - The number of available Redis databases is set to 16, but you can change this in the redis.conf configuration file.
        ```
    - Next, set a key using the Python shell:
        ```
        >>> r.set('foo', 'bar')
        True
        ```
        ```
        Note:
        - The command returns True, indicating that the key has been successfully created.
    - Now you can retrieve the key using the get() command:
        ```
        >>> r.get('foo')
        b'bar'
        ```
        ```
        As you will note from the preceding code, the methods of Redis follow the Redis command syntax.
        ```
    - Let's integrate Redis into your project.
        - Edit bookmarks/settings.py
            ```
            REDIS_HOST = 'localhost'
            REDIS_PORT = 6379
            REDIS_DB = 0
            ```
<a name="C43"></a>
- Storing item views in Redis
    - Tujuan:
        - Let's find a way to store the total number of times an image has been viewed.
        - If you implement this using the Django ORM, it will involve a SQL UPDATE query every time an image is displayed.
        - If you use Redis instead, you just need to increment a counter stored in memory, resulting in a much better performance and less overhead.
    - Edit images/views.py
        - add the following code to it after the existing import statements:

            ```py
            import redis
            from django.conf import settings

            # connect to redis
            r = redis.Redis(host=settings.REDIS_HOST,
                            port=settings.REDIS_PORT,
                            db=settings.REDIS_DB)

            ```
        - modify the `image_detail` view, like this:

            ```py

            def image_detail(request, id, slug):
                image = get_object_or_404(Image, id=id, slug=slug)
                # increment total image views by 1
                total_views = r.incr(f'image:{image.id}:views')
                return render(request,
                                'images/image/detail.html',
                                {'section': 'images', 'image': image, 'total_views': total_views }
                            )
            ```
            ```
            Note:
            - In this view, you use the incr command that increments the value of a given key by 1. If the key doesn't exist, the incr command creates it.
            - The incr() method returns the final value of the key after performing the operation.
            - You store the value in the total_views variable and pass it in the template context.
            - You build the Redis key using a notation, such as object-type:id:field (for example, image:33:id).
            ```
            ```
            " The convention for naming Redis keys is to use a colon sign as a separator for creating namespaced keys.
            By doing so, the key names are especially verbose and related keys share part of the same schema in their names.
            ```
        - Edit templates/images/image/detail.html
            - add the following code to it after the existing `<span class="count">` element:

                ```html
                <span class="count">
                {{ total_views }} view{{ total_views|pluralize }}
                </span>
                ```
        - Run:
            - open an image detail page in your browser and reload it several times.
            - You will see that each time the view is processed, the total views displayed is incremented by 1.
            - You have successfully integrated Redis into your project to store item counts.
<a name="C44"></a>
- Storing a ranking in Redis
    - Tujuan:
        - Let's build something more complex with Redis. You will create a ranking of the most viewed images in your platform.
        - For building this ranking, you will use Redis sorted sets.
        - A sorted set is a non-repeating collection of strings in which every member is associated with a score. Items are sorted by their score.
    - Edit images/views.py
        - make the `image_detail` view look as follows:

            ```py

            def image_detail(request, id, slug):
                image = get_object_or_404(Image, id=id, slug=slug)
                # increment total image views by 1
                total_views = r.incr(f'image:{image.id}:views')
                # increment image ranking by 1
                r.zincrby('image_ranking', 1, image.id)

                return render(request,
                            'images/image/detail.html',
                            {'section': 'images',
                            'image': image,
                            'total_views': total_views})
            ```
            ```
            Note:
            - You use the zincrby() command to store image views in a sorted set with the image:ranking key.
            - You will store the image id and a related score of 1, which will be added to the total score of this element in the sorted set.
            - This will allow you to keep track of all image views globally and have a sorted set ordered by the total number of views.
            ```
    - create a new view to display the ranking of the most viewed images.
        - Edit images/views.py

            ```py
            @login_required
            def image_ranking(request):
                # get image ranking dictionary
                image_ranking = r.zrange('image_ranking', 0, -1,   desc=True)[:10]
                image_ranking_ids = [int(id) for id in image_ranking]
                # get most viewed images
                most_viewed = list(Image.objects.filter(id__in=image_ranking_ids))
                most_viewed.sort(key=lambda x: image_ranking_ids.index(x.id))

                return render(request,
                            'images/image/ranking.html',
                            {'section': 'images',
                            'most_viewed': most_viewed})

            ```
            ```
            The image_ranking view works like this:
            1. You use the zrange() command to obtain the elements in the sorted set.
                - This command expects a custom range according to the lowest and highest score.
                - Using 0 as the lowest and -1 as the highest score, you are telling Redis to return all elements in the sorted set.
                - You also specify desc=True to retrieve the elements ordered by descending score. Finally, you slice the results using [:10] to get the first 10 elements with the highest score.
            2. You build a list of returned image IDs and store it in the image_ranking_ids variable as a list of integers.
                - You retrieve the Image objects for those IDs and force the query to be executed using the list() function.
                - It is important to force the QuerySet execution because you will use the sort() list method on it (at this point, you need a list of objects instead of a QuerySet).
            3. You sort the Image objects by their index of appearance in the image ranking.
                - Now you can use the most_viewed list in your template to display the 10 most viewed images.
            ```
    - templates/images/image/ranking.html
        - add the following code to it:

            ```html

            {% extends "base.html" %}
            {% block title %}Images ranking{% endblock %}

            {% block content %}
                <h1>Images ranking</h1>
                <ol>
                    {% for image in most_viewed %}
                    <li>
                        <a href="{{ image.get_absolute_url }}">
                            {{ image.title }}
                        </a>
                    </li>
                    {% endfor %}
                </ol>
            {% endblock %}
            ```
            ```
            Note:
                - The template is pretty straightforward.
                - You iterate over the Image objects contained in the most_viewed list and display their names, including a link to the image detail page.
            ```
    - Edit images/urls.py

        ```py
        path('ranking/', views.image_ranking, name='ranking'),
        ```
    - Run
        - python manage.py runserver
        - access your site in your web browser, and load the image detail page multiple times for different images.
        - http://127.0.0.1:8000/images/ranking/
        - You should be able to see an image ranking,
        - You just created a ranking with Redis!
<a name="C45"></a>
- Next steps with Redis
- Tujuan:
    - Redis is not a replacement for your SQL database, but it does offer fast in-memory storage that is more suitable for certain tasks.
    - Add it to your stack and use it when you really feel it's needed.
    - The following are some scenarios in which Redis could
    be useful:
        - Counting:
            - As you have seen, it is very easy to manage counters with Redis.
            - You can use incr() and incrby() for counting stuff.
        - Storing latest items:
            - You can add items to the start/end of a list using lpush() and rpush().
            - Remove and return the first/last element using lpop() / rpop().
            - You can trim the list's length using ltrim() to maintain its length.
        - Queues: In addition to push and pop commands, Redis offers the blocking of queue commands.
        - Caching:
            - Using expire() and expireat() allows you to use Redis as a cache.
            - You can also find third-party Redis cache backends for Django.
        - Pub/sub: Redis provides commands for subscribing/unsubscribing and sending messages to channels.
        - Rankings and leaderboards: Redis sorted sets with scores make it very easy to create leaderboards.
        - Real-time tracking: Redis's fast I/O makes it perfect for real-time scenarios.
