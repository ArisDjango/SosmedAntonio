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
- model dari `account` apps
    - model.py
    - python manage.py makemigrations account
    - python manage.py migrate


<a name="A2"></a>
### Menggunakan Django authentication framework
    • AuthenticationMiddleware: Associates users with requests using sessions
    • SessionMiddleware: Handles the current session across requests
    The authentication framework also includes the following models:
        • User: A user model with basic fields; the main fields of this model are username, password, email, first_name, last_name, and is_active
        • Group: A group model to categorize users
        • Permission: Flags for users or groups to perform certain actions
<a name="A21"></a>
- login view ===========================
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
- Using Django authentication views
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
- Login and logout views
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
- Changing password views
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
- Resetting password views
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
### User registration and user profiles
- Saat ini user yang telah terdaftar di db(didaftarkan admin), bisa login, logout, merubah password, reset password. 
- sekarang saatnya membuat anonymous visitor agar bisa membuat akun user.
<a name="A31"></a>

- User registration
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
- Extending the user model
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
- Using a custom user model
    - bisa juga menggunakan custom user model, implementasi: https://docs.djangoproject.com/en/3.0/topics/auth/customizing/#substituting-a-custom-user-model.

<a name="A34"></a>
- Using the messages framework
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
### Building a custom authentication backend
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
### Adding social authentication to your site
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
- Running the development server through HTTPS
    - pip install django-extensions
    - settings.py --> INSTALLED_APPS --> 'django_extensions',
    - pip install werkzeug
    - pip install pyOpenSSL
    - python manage.py runserver_plus --cert-file cert.crt
    - https://mysite.com:8000/account/login/ --> menggunakan https, maka akan muncul peringatan untrusted image

<a name="A52"></a>
- Authentication using Facebook
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
    - Authentication using Twitter
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
- Cleaning form fields
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
- Overriding the save() method of a ModelForm
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
- Building a bookmarklet with jQuery
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
### Creating a detail view for images
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
### Adding AJAX actions with jQuery
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
- Cross-site request forgery in AJAX requests
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
- Performing AJAX requests with jQuery
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
### Creating custom decorators for your views
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
### Adding AJAX pagination to your list views
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
    - Open your browser again and click on a user who has bookmarked some images. you will see like/unlike button and like field
You will see profile details, as follows:
<a name="C13"></a>
- C.1.3. Building an AJAX view to follow users

<a name="C2"></a>
- Building a generic activity stream application
<a name="C21"></a>
- Using the contenttypes framework
<a name="C22"></a>
- Adding generic relations to your models
<a name="C23"></a>
- Avoiding duplicate actions in the activity stream
<a name="C24"></a>
- Adding user actions to the activity stream
<a name="C25"></a>
- Displaying the activity stream
<a name="C26"></a>
- Optimizing QuerySets that involve related objects
<a name="C27"></a>
- Using select_related()
<a name="C28"></a>
Using prefetch_related()
<a name="C29"></a>
Creating templates for actions
<a name="C3"></a>
### Using signals for denormalizing counts
<a name="C31"></a>
- Working with signals
<a name="C32"></a>
- Application configuration classes
<a name="C4"></a>
- Using Redis for storing item views
<a name="C41"></a>
- Installing Redis
<a name="C42"></a>
- Using Redis with Python
<a name="C43"></a>
- Storing item views in Redis
<a name="C44"></a>
- Storing a ranking in Redis
<a name="C45"></a>
- Next steps with Redis
