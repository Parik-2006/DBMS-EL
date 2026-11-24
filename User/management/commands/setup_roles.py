"""
Create the role groups used for authorization (idempotent).

* Analyst         - may submit analyst reviews (User.submit_review); a review can
                    finalize NEEDS_REVIEW decisions in the analyst's own tenant.
* Senior Analyst  - additionally may override FINAL / CONFIDENT_ML decisions
                    (User.override_final_decision).
Administrators are Django superusers. Normal users get no extra permissions.

Assign users with the Django admin or:
    python manage.py setup_roles --add-analyst <username>
"""

from django.core.management.base import BaseCommand, CommandError

ROLES = {
    'Analyst': ['submit_review'],
    'Senior Analyst': ['submit_review', 'override_final_decision'],
}


class Command(BaseCommand):
    help = "Create Analyst / Senior Analyst groups and optionally add a user."

    def add_arguments(self, parser):
        parser.add_argument('--add-analyst', metavar='USERNAME')
        parser.add_argument('--add-senior-analyst', metavar='USERNAME')

    def handle(self, *args, **options):
        from django.contrib.auth.models import Group, Permission, User
        from django.contrib.contenttypes.models import ContentType
        from User.models import AnalystReview

        ctype = ContentType.objects.db_manager('default').get_for_model(AnalystReview)
        groups = {}
        for name, codenames in ROLES.items():
            group, _ = Group.objects.using('default').get_or_create(name=name)
            perms = []
            for codename in codenames:
                perm, _ = Permission.objects.using('default').get_or_create(
                    codename=codename, content_type=ctype,
                    defaults={'name': codename.replace('_', ' ').capitalize()})
                perms.append(perm)
            group.permissions.add(*perms)
            groups[name] = group
            self.stdout.write(f"role {name}: {codenames}")

        for option, group_name in (('add_analyst', 'Analyst'), ('add_senior_analyst', 'Senior Analyst')):
            username = options.get(option)
            if username:
                try:
                    user = User.objects.using('default').get(username=username)
                except User.DoesNotExist:
                    raise CommandError(f"user {username!r} not found")
                user.groups.add(groups[group_name])
                self.stdout.write(self.style.SUCCESS(f"added {username} to {group_name}"))
