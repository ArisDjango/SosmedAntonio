# SosmedAntonio

## Chapter 1: Building Sosmed
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
    - rename root foleder/core menjadi blogApp
    - cd blogApp
    - python manage.py migrate
    - python manage.py runserver
- Membuat app 'blog'
    - python manage.py startapp blog
    - register di settings.py
- Mendesain blog data model
    - model.py
    - python manage.py makemigrations blog
    - python manage.py migrate