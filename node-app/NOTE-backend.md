## requirement

==================

1.  postman app to make api request
2.  npm init -y
3.  sudo npm i express cors mongoose mongodb-memory-server multer nodemon morgan





## Project setup

===================

1.  create file - server.js
1.  



## Initial Settings

======================

1.  in 'full_api/settings.py' set dotenv_file path (#1)
2.  in 'full_api/settings.py' set (SECRET_KEY=) env-variable in (#2)
3.  in '.env.local' store (SECRET_KEY=) variable (#3)
4.  in 'full_api/settings.py' set (DEBUG=) env-variable in (#4)
5.  in '.env.local' store (DEBUG=) variable (#5)
6.  in 'full_api/settings.py' set (ALLOWED_HOSTS =) env-variable in (#6)
7.  in 'full_api/settings.py' tackle my installed apps {django rest framework} (#7)
8.  in 'full_api/settings.py' setup rest_framework settings {permission classes} (#8)
9.  in 'full_api/settings.py' setup rest_framework settings {authentication classes} (#9)
    - in {DEFAULT_AUTHENTICATION_CLASSES: users.authentication.CustomJWTAuthentication} (#9-1)
    - in {DEFAULT_AUTHENTICATION_CLASSES: rest_framework_simplejwt.authentication.JWTAuthentication} (#9-2)

## Djoser setup

======================

1.  in 'full_api/settings.py' tackle my installed apps {djoser} (#10)
2.  in 'full_api/urls.py' include djoser urls and djoser jwt urls (#11)
3.  in 'full_api/settings.py' setup {static_root, media_url, media_root} (#12)
4.  in 'full_api/settings.py' setup djoser settings dictionary (#13)
    - setup {PASSWORD_RESET_CONFIRM_RETYPE} (#14)
    - setup {SEND_ACTIVATION_EMAIL} (#15)
    - setup {ACTIVATION_URL} (#16)
    - setup {USER_CREATE_PASSWORD_RETYPE} (#17)
    - setup {PASSWORD_RESET_CONFIRM_RETYPE} (#18)
    - setup {PASSWORD_RESET_SHOW_EMAIL_NOT_FOUND} (#19)
    - setup {TOKEN_MODEL} (#20)

## Custom user model

======================

1.  in 'full_api/users/models.py' create {UserAccount} model in (#21)
2.  in 'full_api/users/models.py' create {UserAccountManager} model of objectes in (#21)
3.  in 'full_api/settings.py' set users models to be used in (#22)
4.  migrate users model on users postgreaql db

## AWS SES setup

======================

    explanation: we're going to be using digital ocean spaces wich is very similar to AWS S3 buckets, then also going to have an access secret key, also behind the scenes they're also using the python boto3 package

1.  in 'full_api/settings.py' setup email settings (#23)
2.  in '.env.local' store (

    AWS_SES_ACCESS_KEY_ID =
    AWS_SES_SECRET_ACCESS_KEY =
    AWS_SES_REGION_NAME =
    AWS_SES_FROM_EMAIL =

    ) variable (#24)

3.  on browser going to {aws.amazon.com} create AWS account
4.  in 'full_api/settings.py' setup {DOMAIN =} & {SITE_NAME =} (#25)
5.  in '.env.local' store (DOMAIN =) variable (#26)

## django cors headers setup

==============================

1.  in 'full_api/settings.py' setup corsheaders in (#27)
2.  in 'full_api/settings.py' setup corsheaders MIDDLEWARE in (#28)
3.  in 'full_api/settings.py' setup {CORS_ALLOWED_ORIGINS =} in (#29)
4.  in '.env.local' store (CORS_ALLOWED_ORIGINS =) variable (#30)
5.  in 'full_api/settings.py' setup {CORS_ALLOWED_CREDENTIALS =} in (#31)

## Customizing Authorization and Authentication

===================================================

    explanation: start override the behavior of djoser an simple JWT, so that way i can get the behavior i want instead of having to put that authorization header inside of my requests whenever i want to make an authorized requests, we want this to be managed by HTTP only cookies, that's means cookies that have the HTTP only flag set to True which just prevents js on the frontend from reading the values of our access and refresh tokens when they're stored in the cookies, so it's just a very secure way to store these cookies, and we also need a way to have our authorization process actually read these values.

1.  in 'users/' we crate "authentication.py" file
2.  in 'users/authentication.py' get the header in (#32)
3.  in 'full_api/settings.py' setup {AUTH_COOKIE =} in (#33)
4.  in 'full_api/settings.py' setup custom jwt authentication in (#34)
    now when we make an authorized request we're going to use th cookies
5.  in 'full_api/settings.py' setup cookies settings {
    - AUTH_COOKIE_ACCESS_MAX_AGE =
    - AUTH_COOKIE_REFRESH_MAX_AGE =
    - AUTH_COOKIE_SECURE =
    - AUTH_COOKIE_HTTP_ONLY =
    - AUTH_COOKIE_PATH =
    - AUTH_COOKIE_SAMESITE =
      } in (#35)
6.  in '.env.local' store (AUTH_COOKIE_SECURE=) variable (#36)
7.  in 'users/views.py' import views (#37)
8.  in 'users/views.py' setup token create view (#38)
9.  in 'users/views.py' setup token refrsh view (#39)
10. in 'users/views.py' setup token verify view (#40)
11. in 'users/views.py' setup logout view (#41)
12. in 'users/' create urls.py
13. in 'users/urls.py' import our custom views from 'users/views.py' (#42)
14. in 'users/urls.py' urls patterns (#43)
15. in 'full_api/urls.py' use users urls instead of djoser urls (#44)

## OAtuth2 Setup

===================

1.  in 'full_api/settings.py' setup {social_django} in (#45)
2.  in 'full_api/settings.py' setup {AUTHENTICATION_BACKENDS = } in (#46)
3.  in 'full_api/settings.py' setup {SOCIAL_AUTH_ALLOWED_REDIRECT_URIS = REDIRECT_URLS } in (#47)
4.  in '.env.local' store (REDIRECT_URLS =) variable (#48)
5.  in 'full_api/settings.py' setup {
    SOCIAL_AUTH_GOOGLE_OAUTH2_KEY =
    SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET =
    SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE =
    SOCIAL_AUTH_GOOGLE_OAUTH2_EXTRA_DATA =
    } in (#49)
6.  in '.env.local' store {
    SOCIAL_AUTH_GOOGLE_OAUTH2_KEY =
    SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET =
    } in (#50)

7.  in 'full_api/settings.py' setup {
    SOCIAL_AUTH_FACEBOOK_KEY =
    SOCIAL_AUTH_FACEBOOK_SECRET =
    SOCIAL_AUTH_FACEBOOK_SCOPE =
    SOCIAL_AUTH_FACEBOOK_PROFILE_EXTRA_PARAMS =
    } in (#51)
8.  in '.env.local' store {
    SOCIAL_AUTH_FACEBOOK_KEY =
    SOCIAL_AUTH_FACEBOOK_SECRET =
    } in (#52)
9.  in 'users/views.py' setup custom provider view (#52-1)
10. in 'users/urls.py' custom provider view from 'users/views.py' (#52-2)

## production database settings

=================================

1. in 'full_api/settings.py' setup {DEVELOPMENT_MODE = } in (#53)
2. in '.env.local' store {DEVELOPMENT_MODE = } in (#54)
3. in 'full_api/settings.py' setup {DEVELOPMENT_MODE for database condition } in (#55)
4. in 'full_api/settings.py' setup {DEVELOPMENT_MODE for static and media } in (#56)
5. in 'full_api/settings.py' setup {storages} in (#57)
   note: with "django-storages" we can configure this to work with AWS S3
