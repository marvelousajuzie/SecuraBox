# from django.contrib import admin
# from django.contrib.auth.admin import UserAdmin
# from .models import CustomUser, Pin, SocialMedia, Mail, OnlineBanking
# from .models import AdminSocialMedia, AdminMail, AdminOnlineBank

# class CustomUserAdmin(UserAdmin):
#     # Specify the fields to display in the list view
#     list_display = ('email', 'username', 'is_active', 'is_staff', 'date_joined')
#     # Specify which fields can be searched
#     search_fields = ('email', 'username')
#     # Specify filters to add in the sidebar
#     list_filter = ('is_active', 'is_staff', 'date_joined')

#     # Fields to display in the detail view for user editing
#     fieldsets = (
#         (None, {'fields': ('email', 'password')}),
#         ('Personal info', {'fields': ('username',)}),
#         ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'user_permissions', 'groups')}),
#         ('Important dates', {'fields': ('last_login', 'date_joined')}),
#     )
    
#     # Fields to display in the create/edit forms
#     add_fieldsets = (
#         (None, {
#             'classes': ('wide',),
#             'fields': ('email', 'username', 'password1', 'password2', 'is_active', 'is_staff')
#         }),
#     )

#     # Ensure the model uses the correct manager for creating users
#     add_form_template = None  # Set if you have a custom form template

#     # Ensure to use the correct form fields for creating new users
#     def get_form(self, request, obj=None, **kwargs):
#         form = super().get_form(request, obj, **kwargs)
#         if obj is None:
#             form.base_fields['password1'].widget.attrs.update({'autocomplete': 'new-password'})
#             form.base_fields['password2'].widget.attrs.update({'autocomplete': 'new-password'})
#         return form

#     # Ensure correct form validation for passwords
#     def save_model(self, request, obj, form, change):
#         if not change:
#             obj.set_password(form.cleaned_data.get('password1'))
#         obj.save()

# # Register the custom user model with the Django admin site
# admin.site.register(CustomUser, CustomUserAdmin)


# @admin.register(Pin)
# class PinAdmin(admin.ModelAdmin):
#     list_display = ('user', 'pin')  # Display user and pin_number in the list view
#     search_fields = ('user__username', 'pin_number') 



# # SOCIALS MEDIA
# @admin.register(AdminSocialMedia)
# class AdminSocialMediaAdmin(admin.ModelAdmin):
#     list_display = ('logo', 'platform_name')


# @admin.register(SocialMedia)
# class SocialMediaAdmin(admin.ModelAdmin):
#     list_display = ('email', 'phone_number', 'password', 'profile_url')
#     search_fields = ('platform_name', 'username')


# # Email

# @admin.register(AdminMail)
# class MailAdmin(admin.ModelAdmin):
#     list_display = ('logo', 'mail_name')


# @admin.register(Mail)
# class MailAdmin(admin.ModelAdmin):
#     list_display = ('email', 'phone_number', 'password', 'mail_url')
#     search_fields = ('email_address', 'email_provider')



# #ONLINEBANKING ADMIN
# @admin.register(AdminOnlineBank)
# class AdminOnlineBankAdmin(admin.ModelAdmin):
#     list_display = ('logo', 'bank_name')


# @admin.register(OnlineBanking)
# class OnlineBankingAdmin(admin.ModelAdmin):
#     list_display = ('account_number', 'phone_number', 'password')
#     search_fields = ('email_address', 'email_provider')
