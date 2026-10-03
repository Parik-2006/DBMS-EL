from django.core.management.base import BaseCommand, CommandError
from django.db import connections
from User.db_manager import (
    get_user_db_name,
    register_database_connection,
    ensure_mysql_database_exists,
    fast_bootstrap_user_database,
)
from User.models import UserDatabaseRegistry
from django.contrib.auth.models import User
from django.utils import timezone


class Command(BaseCommand):
    help = "Fast bootstrap schema and migration state for an isolated user database."

    def add_arguments(self, parser):
        parser.add_argument(
            '--user-id',
            type=int,
            help='Numeric ID of the user whose database should be bootstrapped.'
        )
        parser.add_argument(
            '--db-alias',
            type=str,
            help='Explicit database alias to bootstrap (e.g. user_42 or guest_db).'
        )

    def handle(self, *args, **options):
        user_id = options.get('user_id')
        db_alias = options.get('db_alias')

        if not user_id and not db_alias:
            raise CommandError("Provide either --user-id or --db-alias.")

        if user_id:
            try:
                user = User.objects.using('default').get(id=user_id)
                username = user.username
            except User.DoesNotExist:
                username = f"user_{user_id}"

            db_name = get_user_db_name(user_id)
            if not db_alias:
                db_alias = f"user_{user_id}"

            self.stdout.write(f"Ensuring MySQL database exists: {db_name}")
            created = ensure_mysql_database_exists(db_name)
            self.stdout.write(f"Database exists/created (created={created})")

            register_database_connection(db_alias, db_name)
            self.stdout.write(f"Bootstrapping schema for {db_alias} ({db_name})...")
            fast_bootstrap_user_database(db_alias)

            UserDatabaseRegistry.objects.using('default').update_or_create(
                user_id=user_id,
                defaults={
                    'username': username,
                    'database_name': db_name,
                    'status': 'active',
                    'last_used_at': timezone.now(),
                }
            )
            self.stdout.write(self.style.SUCCESS(f"Successfully bootstrapped and registered user database: {db_alias}"))
        else:
            self.stdout.write(f"Bootstrapping schema for alias: {db_alias}...")
            fast_bootstrap_user_database(db_alias)
            self.stdout.write(self.style.SUCCESS(f"Successfully bootstrapped database alias: {db_alias}"))
